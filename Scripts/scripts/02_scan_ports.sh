#!/usr/bin/env bash
# Purpose: identify TCP services on hosts previously discovered IN approved scope.
# Usage: bash scripts/02_scan_ports.sh config/scope.txt results/lab1/live_hosts.txt results/lab1 quick
# Profile: quick (default) or full (all 65,535 TCP ports; takes much longer).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

if [[ $# -lt 3 || $# -gt 4 ]]; then
    printf 'Usage: bash %s <approved_scope.txt> <hosts.txt> <results_directory> [quick|full]\n' "$0" >&2
    exit 2
fi
need python3
need nmap
SCOPE="$1"
HOSTS="$2"
BASE="$3"
PROFILE="${4:-quick}"
case "$PROFILE" in
    quick)
        # Common remote administration, Windows/AD, web, DB, and Linux services.
        PORTS='21,22,25,53,80,88,110,111,135,139,143,389,443,445,464,587,636,993,995,1433,1521,2049,3306,3389,5432,5985,5986,6379,8080,8443'
        ;;
    full) PORTS='1-65535' ;;
    *) printf 'ERROR: Unknown scan profile: %s\n' "$PROFILE" >&2; exit 2 ;;
esac
RUN="$(new_run_dir "$BASE" ports)"

# Refuse out-of-scope hosts (including accidents from a stale hosts.txt file).
python3 "$ROOT/lib/scope.py" hosts "$SCOPE" "$HOSTS" "$RUN/hosts.validated.txt"

# -Pn: these hosts were already discovered, so do not re-require ping success.
# -sT: TCP connect scan works without raw-socket privileges.
# -sV --version-light: probe service versions with a lighter probe intensity.
# -oA: save readable, greppable, and XML results under the same prefix.
# --open: show open ports instead of filling the report with closed ports.
printf 'Scanning %s TCP port profile; this sends network traffic to approved hosts.\n' "$PROFILE"
nmap -Pn -n -sT -sV --version-light -T3 --open \
    -p "$PORTS" -iL "$RUN/hosts.validated.txt" \
    -oA "$RUN/tcp_${PROFILE}" >"$RUN/scan.log" 2>&1

# Report a CSV summary, keeping the raw XML as the authoritative evidence.
python3 "$ROOT/lib/scope.py" ports "$SCOPE" "$RUN/tcp_${PROFILE}.xml" "$RUN/open_ports.csv"
printf '\nScan results: %s\n' "$RUN"
printf 'Review open_ports.csv, then verify findings manually. Open ports are not vulnerabilities.\n'
