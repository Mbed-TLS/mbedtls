#!/usr/bin/env bash
#
# Launch a distributed AFL++ campaign for ONE harness.
#
#   ./run_campaign.sh <harness>
#
# Spawns a fixed set of 8 instances: a main instance, one CMPLOG instance
# (-l 2a), one ASAN instance, and 5 MOpt (-L) secondaries each with a
# different power schedule, each in its own tmux/screen session. Seeds come
# from seeds/<harness>, and a matching dictionary from dict/. Requires
# ./build_targets.sh to have run first.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HERE/bin"
HARNESS="${1:-}"

if [ -z "$HARNESS" ]; then
    echo "usage: $0 <harness>"
    echo "available harnesses:"
    ls "$BIN" 2>/dev/null | sed 's/_[a-z]*$//' | sort -u | sed 's/^/  /'
    exit 1
fi
[ -f "$BIN/${HARNESS}_normal" ] || { echo "ERROR: $BIN/${HARNESS}_normal missing - run ./build_targets.sh"; exit 1; }
SEEDS="$HERE/seeds/$HARNESS"
[ -d "$SEEDS" ] && [ -n "$(ls -A "$SEEDS" 2>/dev/null)" ] || { echo "ERROR: no seeds in $SEEDS"; exit 1; }
OUT="${AFL_OUT_DIR:-$HERE/output}/$HARNESS"; mkdir -p "$OUT"

case "$HARNESS" in
    fuzz_x509crt|fuzz_x509crl|fuzz_x509csr|fuzz_pkcs7|fuzz_x509_verify| \
    fuzz_privkey|fuzz_pubkey) DICT="$HERE/dict/der.dict" ;;
    *) DICT="$HERE/dict/tls.dict" ;;
esac
DICT_FLAG=""; [ -f "$DICT" ] && DICT_FLAG="-x $DICT"

bin_for() { [ -f "$BIN/${HARNESS}_$1" ] && echo "$BIN/${HARNESS}_$1" || echo "$BIN/${HARNESS}_normal"; }

if command -v screen >/dev/null; then SM=screen
elif command -v tmux >/dev/null; then SM=tmux
else echo "ERROR: need tmux or screen"; exit 1; fi

command -v afl-system-config >/dev/null && echo "[i] tip: run 'sudo afl-system-config' once for best performance"

export AFL_AUTORESUME=1 AFL_TESTCACHE_SIZE=500 AFL_IMPORT_FIRST=1 AFL_SKIP_CPUFREQ=1 \
       AFL_FAST_CAL=1 AFL_TRY_AFFINITY=1 AFL_NO_WARN_INSTABILITY=1 AFL_IGNORE_SEED_PROBLEMS=1 \
       AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

launch() {
    local name="$1" flags="$2" bin="$3" xenv="$4"
    local cmd="${xenv:+$xenv }afl-fuzz -i $SEEDS -o $OUT -m none -t 2000+ $DICT_FLAG $flags -- $bin"
    echo "  [$name] $(basename "$bin")  $flags"
    if [ "$SM" = tmux ]; then tmux new-session -d -s "mbtls_${HARNESS}_${name}" "$cmd"
    else screen -dmS "mbtls_${HARNESS}_${name}" bash -c "$cmd"; fi
    sleep 0.3
}

HOST="$(hostname)"; CMPLOG="$(bin_for cmplog)"
echo "[*] $HARNESS: launching 8 instance(s) into $OUT via $SM"

launch "main"   "-M main-$HOST -p explore"   "$(bin_for normal)" "AFL_FINAL_SYNC=1"
launch "cmplog" "-S cmplog -c $CMPLOG -l 2a" "$(bin_for normal)" ""
launch "asan"   "-S asan -p explore"         "$(bin_for asan)"   ""

sc=(fast coe exploit rare seek)
for ((i = 0; i < 5; i++)); do
    launch "mopt$i" "-S mopt$i -L 0 -p ${sc[$i]}" "$(bin_for normal)" ""
done

echo "[+] launched. Monitor: ./campaign_ctl.sh $HARNESS status   |   Stop: ./campaign_ctl.sh $HARNESS stop"
