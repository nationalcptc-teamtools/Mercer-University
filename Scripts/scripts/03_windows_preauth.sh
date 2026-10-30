#!/usr/bin/env bash
# Windows / Active Directory unauthenticated recon.
# PRE-AUTH = no valid user credentials are provided to the target.
# Queries SMB information and tries anonymous shares / LDAP user enumeration.
# Anonymous-denied results are expected and are NOT vulnerabilities by themselves.
# Usage: bash scripts/03_windows_preauth.sh scope.txt live_hosts.txt results/lab1
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
if [[ $# -ne 3 ]]; then echo "Usage: bash $0 <scope.txt> <hosts.txt> <results_dir>" >&2; exit 2; fi
need python3; need nmap; need nxc; need timeout
SCOPE="$1"; HOSTS="$2"; BASE="$3"
RUN="$(new_run_dir "$BASE" windows_preauth)"
python3 "$ROOT/lib/scope.py" hosts "$SCOPE" "$HOSTS" "$RUN/hosts.validated.txt"
python3 "$ROOT/lib/scope.py" normalize "$SCOPE" "$RUN/targets.txt" "$RUN/excluded.txt" >/dev/null
set_exclusions "$RUN/excluded.txt"
# Gate authenticated service tooling behind a basic 389/445 availability check.
nmap -n -Pn -sT -T3 --open -p 389,445 -iL "$RUN/hosts.validated.txt" \
    "${NMAP_EXCLUDES[@]}" -oX "$RUN/windows_ports.xml" >"$RUN/windows_ports.log" 2>&1
python3 "$ROOT/lib/scope.py" service-hosts "$SCOPE" "$RUN/windows_ports.xml" 445 "$RUN/smb_hosts.txt"
python3 "$ROOT/lib/scope.py" service-hosts "$SCOPE" "$RUN/windows_ports.xml" 389 "$RUN/ldap_hosts.txt"
printf 'host\tcheck\texit_code\tlog_path\n' >"$RUN/check_index.tsv"
run_check() {
    local host="$1" label="$2"; shift 2
    local log="$RUN/${host}_${label}.txt" status=0
    echo "  $host — $label"
    {
        printf 'UTC: %s\nHost: %s\nCheck: %s\n\n' "$(date -u -Is)" "$host" "$label"
        timeout 90s "$@" || status=$?
        printf '\nExit status: %s\n' "$status"
    } >"$log" 2>&1
    printf '%s\t%s\t%s\t%s\n' "$host" "$label" "$status" "$log" >>"$RUN/check_index.tsv"
}
while IFS= read -r ip; do
    run_check "$ip" smb_fingerprint nxc smb "$ip"
    run_check "$ip" smb_anonymous_shares nxc smb "$ip" -u '' -p '' --shares
done <"$RUN/smb_hosts.txt"
while IFS= read -r ip; do
    run_check "$ip" ldap_anonymous_users nxc ldap "$ip" -u '' -p '' --users
done <"$RUN/ldap_hosts.txt"
echo "Saved pre-auth logs: $RUN"
