#!/usr/bin/env bash
# CyBears CPTC: authenticated, read-only AD *configuration* triage.
# Requires an authorized Kerberos ticket; never collects hashes or passwords.
# Looks for account properties that WARRANT REVIEW, not confirmed exploits.
# Usage: bash scripts/08_ad_posture.sh scope.txt DC_IP DC_FQDN AD_DOMAIN results_dir
# IMPORTANT: Six LDAP subtree searches can be noticeable on large directories.
# Run once against a designated in-scope DC, with explicit authorization.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
if [[ $# -ne 5 ]]; then
    echo "Usage: bash $0 <scope.txt> <DC_IP> <DC_FQDN> <AD_DOMAIN> <results_dir>" >&2
    exit 2
fi
need python3; need ldapsearch; need timeout; need klist; need getent
SCOPE="$1"; DC_IP="$2"; FQDN="$3"; DOMAIN="${4%.}"; BASE="$5"
# Accept DNS labels only; reject user-supplied LDAP filters or URI components.
if [[ ! "$DOMAIN" =~ ^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$ || ! "$FQDN" =~ ^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$ ]]; then
    echo 'ERROR: Use dotted AD domain and DC FQDN (no protocol or port).' >&2
    exit 2
fi
python3 "$ROOT/lib/scope.py" check-ip "$SCOPE" "$DC_IP" >/dev/null
mapfile -t RESOLVED < <(getent ahostsv4 "$FQDN" | awk '{print $1}' | sort -u)
if [[ ${#RESOLVED[@]} -ne 1 || "${RESOLVED[0]}" != "$DC_IP" ]]; then
    echo 'ERROR: DC hostname must resolve to exactly the approved DC IP.' >&2
    exit 1
fi
if [[ -z "${KRB5CCNAME:-}" ]] || ! klist -s; then
    echo 'ERROR: Authenticate legitimately and set KRB5CCNAME to an active ticket.' >&2
    exit 1
fi
BASE_DN="$(python3 - "$DOMAIN" <<'PY'
import sys
print(','.join('DC=' + p for p in sys.argv[1].split('.')))
PY
)"
RUN="$(new_run_dir "$BASE" ad_posture)"
printf 'check\tstatus\tcandidates\toutput\n' >"$RUN/check_index.tsv"
# LDAP bitwise-match operator 1.2.840.113556.1.4.803 tests UAC flags.
# 4194304 = DONT_REQ_PREAUTH, 524288 = TRUSTED_FOR_DELEGATION.
# Results list DNs only; never request SPN values or sensitive attributes.
check() {
    local label="$1" filter="$2" code=0 count
    echo "AD account posture: $label"
    timeout 90s ldapsearch -LLL -Q -Y GSSAPI -H "ldap://$FQDN" \
        -o ldif-wrap=no -z 200 -b "$BASE_DN" -s sub "$filter" dn \
        >"$RUN/${label}.ldif" 2>"$RUN/${label}.errors.txt" || code=$?
    count="$(grep -ci '^dn:' "$RUN/${label}.ldif" || true)"
    printf '%s\t%d\t%s\t%s\n' "$label" "$code" "$count" "${label}.ldif" >>"$RUN/check_index.tsv"
    if (( code != 0 )); then echo "WARNING: $label returned $code; check error log." >&2; fi
}
# An SPN is normal for a service account; this is an inventory, not evidence
# of a weak password or a Kerberoastable *vulnerability*.
check user_spns '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))'
# Pre-auth disabled is a configuration signal; no AS-REP requests are made.
check preauth_disabled '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
# Delegation presence alone is NOT an abuse path. Review account privileges,
# ACLs, trust paths, service exposure, and intended architecture manually.
check unconstrained_delegation '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))'
check constrained_delegation '(msDS-AllowedToDelegateTo=*)'
check rbcd_configured '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)'
# Key credentials can be legitimate Windows Hello/PKI functionality.
# This only identifies objects with values; it cannot detect shadow abuse.
check key_credentials_configured '(msDS-KeyCredentialLink=*)'
cat >"$RUN/README.txt" <<NOTE
CyBears AD posture triage: $(date -u -Is)
Domain: $DOMAIN | DC: $FQDN ($DC_IP)
Only distinguished names are requested. No hashes, secrets, or ticket requests.
Results identify CONFIGURATION CANDIDATES only. Confirm access/impact manually.
Results may be truncated at 200 entries (check_index.tsv is NOT a total population count).
Six LDAP subtree searches may cause load; do not schedule continuously.
No LDAP referral chasing. Scope checks apply to the initial DC.
NOTE
printf 'Saved candidate-only AD posture checks: %s\n' "$RUN"
