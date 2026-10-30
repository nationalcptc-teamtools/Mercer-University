#!/usr/bin/env bash
# Authenticated read-only-ish AD inventory, after a LEGITIMATE Kerberos login.
# This script REQUIRES an existing ticket cache: no passwords in CLI/history.
# Checks: SMB shares/password policy, LDAP users/groups. No password spraying,
# remote command execution, hash dumping, lateral movement, or exploitation.
# Usage: bash scripts/06_windows_postauth.sh scope.txt DC_IP DC_FQDN results/lab1
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
if [[ $# -ne 4 ]]; then
    echo "Usage: bash $0 <scope.txt> <dc-ip> <dc-fqdn> <results_dir>" >&2; exit 2
fi
need python3; need nxc; need timeout; need getent; need klist
SCOPE="$1"; DC_IP="$2"; FQDN="$3"; BASE="$4"
# A Kerberos SPN expects a hostname, not just an IP. Validate resolution so
# NetExec cannot inadvertently contact a different or out-of-scope system.
if [[ ! "$FQDN" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ || "$FQDN" == *..* ]]; then
    echo 'Provide a valid DNS hostname for the domain controller.' >&2; exit 2
fi
python3 "$ROOT/lib/scope.py" check-ip "$SCOPE" "$DC_IP" >/dev/null
mapfile -t RESOLVED < <(getent ahostsv4 "$FQDN" | awk '{print $1}' | sort -u)
if [[ ${#RESOLVED[@]} -ne 1 || "${RESOLVED[0]}" != "$DC_IP" ]]; then
    echo "ERROR: $FQDN must resolve to exactly $DC_IP on this Kali system." >&2
    echo 'Fix authorized lab DNS or /etc/hosts first; do not skip scope validation.' >&2
    exit 1
fi
if [[ -z "${KRB5CCNAME:-}" ]]; then
    echo 'ERROR: Set KRB5CCNAME to your authorized Kerberos ticket cache.' >&2; exit 1
fi
if ! klist -s; then
    echo 'ERROR: No valid Kerberos ticket; run klist and authenticate legitimately first.' >&2
    exit 1
fi
RUN="$(new_run_dir "$BASE" windows_postauth)"
printf 'host\tcheck\texit_code\tlog_path\n' >"$RUN/check_index.tsv"
run_check() {
    local label="$1"; shift
    local code=0 log="$RUN/${label}.txt"
    echo "Authenticated query: $label"
    {
        printf 'UTC: %s\nHost: %s\nCheck: %s\n\n' "$(date -u -Is)" "$FQDN" "$label"
        timeout 120s "$@" || code=$?
        printf '\nExit status: %s\n' "$code"
    } >"$log" 2>&1
    printf '%s\t%s\t%s\t%s\n' "$FQDN" "$label" "$code" "$log" >>"$RUN/check_index.tsv"
}
# Explicit --use-kcache uses the Kerberos ticket, not a password on argv.
run_check smb_shares nxc smb "$FQDN" --use-kcache --shares
run_check smb_password_policy nxc smb "$FQDN" --use-kcache --pass-pol
run_check ldap_users nxc ldap "$FQDN" --use-kcache --users
run_check ldap_groups nxc ldap "$FQDN" --use-kcache --groups
echo "Saved post-auth inventory: $RUN"
