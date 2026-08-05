#!/usr/bin/env bash
#
# Build and run gen_tls_seeds.c to produce fuzz_client seeds.
#
#   ./build_tls_seeds.sh [output_dir]      (default: seeds/fuzz_client)
#
# The generator MUST be built with the same deterministic-RNG configuration as
# the campaign binaries (see the "Deterministic RNG" section of README.md), or
# the client it drives will pick different random values than the harness does
# and the recorded server flight will not replay. That means undefining
# MBEDTLS_PSA_BUILTIN_GET_ENTROPY through TF_PSA_CRYPTO_USER_CONFIG_FILE - the
# PSA config does not consult MBEDTLS_USER_CONFIG_FILE, so an #undef placed
# there is silently ignored.
#
# Seeds are validated by replaying them through the generator's own build; use
# validate_tls_seeds.sh against a coverage build to confirm they reach depth.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "$HERE/../../.." && pwd)"
OUT="${1:-$HERE/seeds/fuzz_client}"
BUILD="${GEN_BUILD_DIR:-/tmp/mbedtls_seedgen}"
JOBS="${GEN_JOBS:-$(nproc)}"

command -v cmake >/dev/null || { echo "ERROR: cmake not found"; exit 1; }

mkdir -p "$BUILD" "$OUT"

UCFG="$BUILD/user_config.h"
printf '#define MBEDTLS_PLATFORM_TIME_ALT\n' > "$UCFG"
PCFG="$BUILD/psa_user_config.h"
printf '#undef MBEDTLS_PSA_BUILTIN_GET_ENTROPY\n' > "$PCFG"

echo "[*] configuring generator build in $BUILD"
if ! cmake -S "$SRC" -B "$BUILD" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        -DMBEDTLS_USER_CONFIG_FILE="$UCFG" \
        -DTF_PSA_CRYPTO_USER_CONFIG_FILE="$PCFG" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        > "$BUILD/configure.log" 2>&1; then
    echo "[!] configure failed:"; tail -25 "$BUILD/configure.log"; exit 1
fi

# Building fuzz_client pulls in every library and test-helper object the
# generator needs, and gives us a link line to copy.
echo "[*] building libraries (-j $JOBS)"
if ! cmake --build "$BUILD" --target fuzz_client -j "$JOBS" > "$BUILD/build.log" 2>&1; then
    echo "[!] build failed:"; tail -30 "$BUILD/build.log"; exit 1
fi

LT="$BUILD/programs/fuzz/CMakeFiles/fuzz_client.dir/link.txt"
[ -f "$LT" ] || { echo "ERROR: no link.txt at $LT"; exit 1; }

# Reuse fuzz_client's own compile flags so the generator sees an identical
# configuration, then reuse its link line with the harness object swapped out.
FLAGS=$(python3 - "$BUILD/compile_commands.json" <<'PY'
import json, shlex, sys
db = json.load(open(sys.argv[1]))
ent = next(e for e in db if e["file"].endswith("fuzz_client.c"))
parts = shlex.split(ent.get("command") or " ".join(ent["arguments"]))
print(" ".join(p for p in parts if p.startswith(("-I", "-D"))))
PY
)
[ -n "$FLAGS" ] || { echo "ERROR: could not extract compile flags"; exit 1; }

echo "[*] compiling gen_tls_seeds.c"
clang -O2 -g $FLAGS -c "$HERE/gen_tls_seeds.c" -o "$BUILD/gen_tls_seeds.o" || \
    cc -O2 -g $FLAGS -c "$HERE/gen_tls_seeds.c" -o "$BUILD/gen_tls_seeds.o" || exit 1

echo "[*] linking"
(
  cd "$BUILD/programs/fuzz" || exit 1
  LINE=$(cat "$LT")
  # swap fuzz_client.c.o for our object, drop the fuzz_onefile driver (we have
  # our own main()), and retarget the output
  NEW=${LINE//CMakeFiles\/fuzz_client.dir\/fuzz_client.c.o/$BUILD/gen_tls_seeds.o}
  NEW=${NEW//\"CMakeFiles\/fuzz_client.dir\/__\/__\/tf-psa-crypto\/programs\/fuzz\/fuzz_onefile.c.o\"/}
  NEW=${NEW//-o fuzz_client/-o $BUILD/gen_tls_seeds}
  eval "$NEW"
) || { echo "[!] link failed"; exit 1; }

echo "[*] generating seeds into $OUT"
"$BUILD/gen_tls_seeds" "$OUT"
