#!/usr/bin/env bash
# Purpose: determine which permitted IPv4 hosts respond to several discovery probes.
# Usage: bash scripts/01_discover_hosts.sh config/scope.txt results/lab1
# No exploitation, credential attacks, or vulnerability modules are run here.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

if [[ $# -ne 2 ]]; then
    printf 'Usage: bash %s <approved_scope.txt> <results_directory>\n' "$0" >&2
    exit 2
fi
need python3
need nmap
need sudo
# Keep the evidence owned by your regular Kali user. Only raw Nmap probes
# need elevated rights. Run `sudo -v` first to cache permission safely.
if (( EUID == 0 )); then
    printf 'ERROR: Run as your regular user, not sudo bash. First run: sudo -v\n' >&2
    exit 1
fi
if ! sudo -n true >/dev/null 2>&1; then
    printf 'ERROR: Run sudo -v first to authorize the Nmap probes.\n' >&2
    exit 1
fi
SCOPE="$1"
BASE="$2"
RUN="$(new_run_dir "$BASE" discovery)"

# Normalize/validate CIDRs: no DNS names, unexpected IPv6, or very broad ranges.
python3 "$ROOT/lib/scope.py" normalize "$SCOPE" "$RUN/scope.validated.txt"

# Use 3 complementary discovery methods. Nmap can detect up hosts even if ICMP
# is blocked, but no single method guarantees detection of every live machine.
# XML is saved for reproducible parsing and the raw Nmap logs for troubleshooting.
# -sn: host discovery ONLY; -n: no external DNS lookups; -T3: moderate timing.
# Only Nmap is elevated. The shell redirects XML to user-owned evidence files;
# -oX - tells Nmap to write its machine-readable XML to standard output.
printf '[1/3] ICMP echo discovery\n'
sudo -n nmap -sn -n -T3 -PE -iL "$RUN/scope.validated.txt" \
    -oX - >"$RUN/icmp.xml" 2>"$RUN/icmp.log"

printf '[2/3] TCP SYN discovery\n'
sudo -n nmap -sn -n -T3 -PS22,80,443,445,3389 -iL "$RUN/scope.validated.txt" \
    -oX - >"$RUN/syn.xml" 2>"$RUN/syn.log"

printf '[3/3] TCP ACK discovery\n'
sudo -n nmap -sn -n -T3 -PA22,80,443,445,3389 -iL "$RUN/scope.validated.txt" \
    -oX - >"$RUN/ack.xml" 2>"$RUN/ack.log"

# Merge all UP results, deduplicate, and document which probes found each host.
python3 "$ROOT/lib/scope.py" discovery "$SCOPE" \
    "$RUN/live_hosts.txt" "$RUN/discovery_methods.csv" \
    "$RUN/icmp.xml" "$RUN/syn.xml" "$RUN/ack.xml"

# A stable convenience copy makes subsequent commands simple. The versioned
# discovery run still preserves the original list even after another discovery.
cp "$RUN/live_hosts.txt" "$BASE/live_hosts.txt"
printf '\nRun evidence: %s\nNext step input: %s/live_hosts.txt\n' "$RUN" "$BASE"
