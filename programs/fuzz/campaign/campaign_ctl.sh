#!/usr/bin/env bash
#
# Monitor / stop / inspect a running campaign.
#   ./campaign_ctl.sh <harness> {status|stop|crashes}
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${1:-}"; ACTION="${2:-status}"
OUT="${AFL_OUT_DIR:-$HERE/output}/$HARNESS"

[ -z "$HARNESS" ] && { echo "usage: $0 <harness> {status|stop|crashes}"; exit 1; }
[ -d "$OUT" ] || { echo "no campaign output at $OUT"; exit 1; }

case "$ACTION" in
    status)
        afl-whatsup -s "$OUT" 2>/dev/null || echo "(afl-whatsup unavailable)"
        ;;
    stop)
        echo "[*] stopping campaign for $HARNESS ..."
        for fs in "$OUT"/*/fuzzer_stats; do
            [ -f "$fs" ] || continue
            pid=$(awk '/^fuzzer_pid/{print $3}' "$fs")
            [ -n "${pid:-}" ] && kill -INT "$pid" 2>/dev/null && echo "    SIGINT -> $pid"
        done
        sleep 2
        for s in $(tmux ls 2>/dev/null | grep -o "mbtls_${HARNESS}_[^:]*" || true); do tmux kill-session -t "$s" 2>/dev/null; done
        for s in $(screen -ls 2>/dev/null | grep -o "mbtls_${HARNESS}_[^[:space:]]*" || true); do screen -S "$s" -X quit 2>/dev/null; done
        echo "[+] stopped"
        ;;
    crashes)
        total=0
        for d in "$OUT"/*/crashes; do
            [ -d "$d" ] || continue
            c=$(find "$d" -maxdepth 1 -name 'id:*' 2>/dev/null | wc -l)
            [ "$c" -gt 0 ] && echo "  $(basename "$(dirname "$d")"): $c" && total=$((total + c))
        done
        echo "  --- total crash files: $total"
        echo
        echo "Triage: casr-afl -i $OUT -o casr_out   (or afl-tmin -i <crash> -o min -- $HERE/bin/${HARNESS}_normal)"
        ;;
    *)
        echo "usage: $0 <harness> {status|stop|crashes}"; exit 1 ;;
esac
