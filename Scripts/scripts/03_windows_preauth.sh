#!/usr/bin/env bash
# Purpose: basic Windows/Active Directory information gathering BEFORE login.
# Usage: bash scripts/03_windows_preauth.sh config/scope.txt results/lab1/live_hosts.txt results/lab1
# No password spray, brute force, vulnerability exploitation, or credential dumping.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

if [[ $# -ne 3 ]]; then
    printf 'Usage: bash %s <approved_scope.txt> <hosts.txt> <results_directory>\n' "$0" >&2
    exit 2
fi
need python3
need nmap
need nxc
need timeout
SCOPE="$1"
HOSTS="$2"
BASE="$3"
RUN="$(new_run_dir "$BASE" windows_preauth)"

# Always verify against the approved CIDRs before querying a domain service.
python3 "$ROOT/lib/scope.py" hosts "$SCOPE" "$HOSTS" "$RUN/hosts.validated.txt"

# Gate NetExec checks: only query hosts with SMB (445) or LDAP (389) open.
# -sT is a normal connect scan; this initial probe is not an exploit.
nmap -Pn -n -sT -T3 --open -p 389,445 -iL "$RUN/hosts.validated.txt" \
    -oX "$RUN/windows_ports.xml" >"$RUN/windows_ports.log" 2>&1
python3 "$ROOT/lib/scope.py" service-hosts "$SCOPE" "$RUN/windows_ports.xml" 445 "$RUN/smb_hosts.txt"
python3 "$ROOT/lib/scope.py" service-hosts "$SCOPE" "$RUN/windows_ports.xml" 389 "$RUN/ldap_hosts.txt"

# Run one labeled check at a time. Each command's exact output and exit status
# are retained, including failures, instead of converting errors into findings.
run_check() {
    local host="$1" label="$2"; shift 2
    local log="$RUN/${host}_${label}.txt" status=0
    printf '  %-18s %s\n' "$host" "$label"
    {
        printf 'UTC: %s\nHost: %s\nCheck: %s\n\n' "$(date -u -Is)" "$host" "$label"
        # A failed or blocked anonymous request is a normal result, not a vuln.
        timeout 90s "$@" || status=$?
        printf '\nExit status: %s\n' "$status"
    } >"$log" 2>&1
    printf '%s\t%s\t%s\t%s\n' "$host" "$label" "$status" "$log" >>"$RUN/check_index.tsv"
}

printf 'host\tcheck\texit_code\tlog_path\n' >"$RUN/check_index.tsv"

# SMB negotiation reveals basic Windows / Samba info and signing indicators.
# Null-session shares asks once with EMPTY credentials. It does not guess any.
while IFS= read -r host; do
    run_check "$host" smb_fingerprint nxc smb "$host"
    run_check "$host" smb_anonymous_shares nxc smb "$host" -u '' -p '' --shares
done <"$RUN/smb_hosts.txt"

# Anonymous LDAP user enumeration may be denied; treat that as a limitation.
while IFS= read -r host; do
    run_check "$host" ldap_anonymous_users nxc ldap "$host" -u '' -p '' --users
done <"$RUN/ldap_hosts.txt"

printf '\nSaved results: %s\n' "$RUN"
printf 'Read check_index.tsv and the per-host logs. Verify every possible finding manually.\n'
