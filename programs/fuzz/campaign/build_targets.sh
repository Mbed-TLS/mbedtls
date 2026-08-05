#!/usr/bin/env bash
#
# Build in-repo Mbed TLS fuzz harnesses for AFL++.
#
#   ./build_targets.sh [harness ...]
#
# With no arguments every harness is built. Pass one or more harness names to
# build only those (e.g. ./build_targets.sh fuzz_client) - the shared library is
# still compiled once as a dependency, but the other harness targets are skipped.
# A targeted build reuses its per-variant build dir for a fast incremental
# rebuild; a full build wipes it first. AFL_CLEAN=1 forces a from-scratch build,
# AFL_CLEAN=0 forces reuse of the existing build dir.
#
# Produces five instrumented variants of each harness in ./bin :
#   normal   afl-clang-fast, plain               -> main fuzzing binary
#   cmplog   AFL_LLVM_CMPLOG=1                    -> used via afl-fuzz -c
#   asan     AFL_USE_ASAN=1 AFL_USE_UBSAN=1       -> sanitizer instance
#   laf      AFL_LLVM_LAF_ALL=1                   -> comparison splitting
#   cfisan   AFL_USE_CFISAN=1                     -> control-flow integrity
#
# The harnesses expose LLVMFuzzerTestOneInput(); AFL++'s persistent libFuzzer
# driver (libAFLDriver.a) is presented to CMake as libFuzzingEngine so the
# targets get persistent mode automatically (instead of the single-shot
# fuzz_onefile.c driver). MBEDTLS_PLATFORM_TIME_ALT is enabled so dummy_init()
# pins a constant clock, matching programs/fuzz/README.md.
#
# The full configure+compile output is streamed live to the terminal (and to
# $BUILD/<variant>.log) and a heartbeat fires every HEARTBEAT seconds even while
# the output is quiet, so a slow build or one stuck on a single file is obvious.
# Parallelism is bounded to AFL_BUILD_JOBS (default: nproc) so the memory-heavy
# laf/cmplog compiles cannot fork-storm a low-RAM box into swap. Lower it (e.g.
# AFL_BUILD_JOBS=4) if the build thrashes. Select a subset of variants with
# AFL_VARIANTS (e.g. AFL_VARIANTS="normal cmplog asan") to skip the slow laf one.
# Set AFL_VERBOSE=1 to also print every compiler command line.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "$HERE/../../.." && pwd)"
BIN="$HERE/bin"
BUILD="${AFL_BUILD_DIR:-/tmp/mbedtls_afl_campaign}"
JOBS="${AFL_BUILD_JOBS:-$(nproc)}"
VARIANTS="${AFL_VARIANTS:-normal cmplog asan laf cfisan}"
HEARTBEAT="${AFL_HEARTBEAT:-15}"
ALL_HARNESSES="fuzz_client fuzz_server fuzz_dtlsclient fuzz_dtlsserver \
fuzz_x509crt fuzz_x509crl fuzz_x509csr fuzz_pkcs7 \
fuzz_ssl_session fuzz_ssl_context fuzz_dtls_record fuzz_x509_verify \
fuzz_privkey fuzz_pubkey"

# fuzz_privkey/fuzz_pubkey live in the tf-psa-crypto submodule, so their
# executables land under a different build subdirectory than the mbedtls ones.
harness_build_path() {
    case "$1" in
        fuzz_privkey|fuzz_pubkey) echo "tf-psa-crypto/programs/fuzz/$1" ;;
        *)                        echo "programs/fuzz/$1" ;;
    esac
}

case "${1:-}" in
    -h|--help)
        echo "usage: $0 [harness ...]   (default: build all harnesses)"
        echo "harnesses: $ALL_HARNESSES"
        exit 0 ;;
esac

if [ "$#" -gt 0 ]; then
    HARNESSES="$*"
    for h in $HARNESSES; do
        case " $ALL_HARNESSES " in
            *" $h "*) ;;
            *) echo "ERROR: unknown harness '$h'"; echo "available: $ALL_HARNESSES"; exit 1 ;;
        esac
    done
    CLEAN="${AFL_CLEAN:-0}"
else
    HARNESSES="$ALL_HARNESSES"
    CLEAN="${AFL_CLEAN:-1}"
fi

VERBOSE_FLAG=""; [ "${AFL_VERBOSE:-0}" = 1 ] && VERBOSE_FLAG="--verbose"

command -v afl-clang-fast >/dev/null || { echo "ERROR: afl-clang-fast not on PATH (install AFL++)"; exit 1; }

DRV=""
for p in "$(afl-clang-fast -print-file-name=libAFLDriver.a 2>/dev/null)" \
         /usr/local/lib/afl/libAFLDriver.a /usr/lib/afl/libAFLDriver.a; do
    [ -f "$p" ] && { DRV="$p"; break; }
done
[ -n "$DRV" ] || { echo "ERROR: libAFLDriver.a not found; build AFL++ utils/aflpp_driver"; exit 1; }

missing=""
for f in framework/CMakeLists.txt tf-psa-crypto/framework/CMakeLists.txt; do
    [ -f "$SRC/$f" ] || missing="$missing $f"
done
if [ -n "$missing" ]; then
    echo "ERROR: required submodule content missing under $SRC :"
    for f in $missing; do echo "         $f"; done
    echo
    echo "  These are git submodules. A plain 'git submodule update --init' does NOT"
    echo "  fetch the framework nested inside tf-psa-crypto - you must use --recursive:"
    echo
    echo "      git -C $SRC submodule update --init --recursive"
    echo
    echo "  Current submodule state below ('-' prefix = not initialized):"
    git -C "$SRC" submodule status --recursive 2>/dev/null | sed 's/^/      /' \
        || echo "      (not a git checkout - download the full release archive from GitHub)"
    exit 1
fi

FE="$BUILD/fe"; mkdir -p "$FE"; cp -f "$DRV" "$FE/libFuzzingEngine.a"
UCFG="$BUILD/user_config.h"; printf '#define MBEDTLS_PLATFORM_TIME_ALT\n' > "$UCFG"

# Drop the platform entropy source so the constant NV seed installed by
# fuzz_common.c is the ONLY one, making the RNG reproducible run to run.
# Without this, every execution draws fresh randomness, so a client's
# ClientHello random and 32-byte legacy_session_id differ each time and no
# recorded server response can ever echo them back - the client handshake
# harnesses can then never get past ServerHello (verified: TLS 1.3
# parse_key_share/encrypted_extensions/Finished stay at 0 coverage). It also
# stabilises AFL++'s edge feedback, which random values otherwise perturb.
# This knob lives in the PSA config, which honours its own user-config macro,
# not MBEDTLS_USER_CONFIG_FILE. Fuzzing only - never ship this.
PCFG="$BUILD/psa_user_config.h"
if [ "${AFL_DETERMINISTIC_RNG:-1}" = 1 ]; then
    printf '#undef MBEDTLS_PSA_BUILTIN_GET_ENTROPY\n' > "$PCFG"
else
    : > "$PCFG"
fi
mkdir -p "$BIN"

echo "[i] source:   $SRC"
echo "[i] build:    $BUILD   (logs: <variant>.log)"
echo "[i] output:   $BIN"
echo "[i] variants: $VARIANTS"
echo "[i] harness:  $HARNESSES"
echo "[i] jobs:     -j $JOBS   heartbeat: ${HEARTBEAT}s   verbose: ${AFL_VERBOSE:-0}   clean: $CLEAN"
echo "[i] deterministic RNG: ${AFL_DETERMINISTIC_RNG:-1}  (0 disables; see comment above)"
echo "[i] binaries are installed by rename, so rebuilding during a live campaign is"
echo "    safe, but running instances keep the old code until you restart them."
echo "[i] full compile output streams below; laf/cmplog are the slow ones."

heartbeat() {
    local variant="$1" log="$2" t0="$3"
    while :; do
        sleep "$HEARTBEAT"
        printf '    ...... [%s] alive, %ss elapsed | last: %s\n' \
            "$variant" "$((SECONDS - t0))" "$(tail -1 "$log" 2>/dev/null)"
    done
}

build_variant() {
    local variant="$1"; shift
    local dir="$BUILD/$variant" log="$BUILD/$variant.log" t0=$SECONDS
    echo
    echo "==================== variant: $variant  (-j $JOBS) ===================="
    [ "$CLEAN" = 1 ] && rm -rf "$dir"; : > "$log"

    echo "[*] [$variant] configuring (cmake -S $SRC -B $dir) ..."
    if ! env "$@" AFL_QUIET=1 LIBRARY_PATH="$FE" \
        cmake -S "$SRC" -B "$dir" \
            -DCMAKE_C_COMPILER=afl-clang-fast -DCMAKE_CXX_COMPILER=afl-clang-fast++ \
            -DBUILD_SHARED_LIBS=OFF -DMBEDTLS_USER_CONFIG_FILE="$UCFG" \
            -DTF_PSA_CRYPTO_USER_CONFIG_FILE="$PCFG" \
            -DFUZZINGENGINE_LIB="$FE/libFuzzingEngine.a" 2>&1 | tee -a "$log"; then
        echo "[!] configure FAILED for $variant (full log: $log) - skipping"; return 1
    fi
    echo "[+] [$variant] configured in $((SECONDS - t0))s; compiling $(echo $HARNESSES | wc -w) targets ..."

    heartbeat "$variant" "$log" "$t0" &
    local hb=$!
    env "$@" AFL_QUIET=1 LIBRARY_PATH="$FE" \
        cmake --build "$dir" --target $HARNESSES -j "$JOBS" $VERBOSE_FLAG 2>&1 | tee -a "$log"
    local rc=${PIPESTATUS[0]}
    kill "$hb" 2>/dev/null; wait "$hb" 2>/dev/null

    if [ "$rc" -ne 0 ]; then
        echo "[!] build FAILED for $variant (rc=$rc, full log: $log) - skipping"; return 1
    fi
    # Install by copy-then-rename, never a plain cp over the destination.
    # cp -f writes into the existing inode, so overwriting a binary that a live
    # afl-fuzz instance is executing corrupts its text pages and kills the
    # campaign minutes later. rename(2) swaps the directory entry instead, so
    # running instances keep the inode they started with and a rebuild during a
    # campaign is safe.
    local h dst
    for h in $HARNESSES; do
        dst="$BIN/${h}_${variant}"
        cp -f "$dir/$(harness_build_path "$h")" "$dst.new" && mv -f "$dst.new" "$dst"
    done
    echo "[+] [$variant] DONE in $((SECONDS - t0))s"
}

for v in $VARIANTS; do
    case "$v" in
        normal) build_variant normal                               ;;
        cmplog) build_variant cmplog AFL_LLVM_CMPLOG=1             ;;
        asan)   build_variant asan   AFL_USE_ASAN=1 AFL_USE_UBSAN=1 ;;
        laf)    build_variant laf    AFL_LLVM_LAF_ALL=1            ;;
        cfisan) build_variant cfisan AFL_USE_CFISAN=1             ;;
        *)      echo "[!] unknown variant '$v' - skipping"         ;;
    esac || true
done

echo
echo "[+] binaries in $BIN :"
ls -1 "$BIN" 2>/dev/null | sed 's/^/    /'
echo
echo "Next: ./run_campaign.sh <harness> [instances]   (e.g. ./run_campaign.sh fuzz_x509crt 8)"
