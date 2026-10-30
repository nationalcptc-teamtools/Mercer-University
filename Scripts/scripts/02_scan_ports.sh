#!/usr/bin/env bash
# Scoped TCP port and service discovery. A version banner is not a vulnerability.
# Usage: bash scripts/02_scan_ports.sh config/scope.txt results/lab1/live_hosts.txt results/lab1 [quick|full|low-noise]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
if [[ $# -lt 3 || $# -gt 4 ]]; then
    echo "Usage: bash $0 <scope.txt> <hosts.txt> <results_dir> [quick|full|low-noise]" >&2; exit 2
fi
need python3; need nmap
SCOPE="$1"; HOSTS="$2"; BASE="$3"; PROFILE="${4:-quick}"
QUICK_PORTS='21,22,25,53,80,88,110,111,135,139,143,389,443,445,464,587,636,993,995,1433,1521,2049,3306,3389,5432,5985,5986,6379,8080,8443'
case "$PROFILE" in
    quick) PORTS="$QUICK_PORTS"; flags=(-T3 -sV --version-light) ;;
    full) PORTS='1-65535'; flags=(-T3 -sV --version-light) ;;
    low-noise) PORTS="$QUICK_PORTS"; flags=(-T2 --max-rate 15 --max-retries 1) ;;
    *) echo "Unknown port profile: $PROFILE" >&2; exit 2 ;;
esac
RUN="$(new_run_dir "$BASE" ports)"
python3 "$ROOT/lib/scope.py" hosts "$SCOPE" "$HOSTS" "$RUN/hosts.validated.txt"
python3 "$ROOT/lib/scope.py" normalize "$SCOPE" "$RUN/targets.txt" "$RUN/excluded.txt" >/dev/null
set_exclusions "$RUN/excluded.txt"
echo "Scanning TCP ports ($PROFILE); network monitors can see these connections."
# -sT: regular TCP connect (no raw socket rights required).
# -Pn: rely on already-validated host list rather than repeated ping probes.
# -n: no DNS lookups; -oA preserves three Nmap output formats.
nmap -Pn -n -sT --open "${flags[@]}" -p "$PORTS" \
    -iL "$RUN/hosts.validated.txt" "${NMAP_EXCLUDES[@]}" \
    -oA "$RUN/tcp_${PROFILE}" >"$RUN/scan.log" 2>&1
python3 "$ROOT/lib/scope.py" ports "$SCOPE" "$RUN/tcp_${PROFILE}.xml" "$RUN/open_ports.csv"
printf 'Saved: %s\n' "$RUN"
