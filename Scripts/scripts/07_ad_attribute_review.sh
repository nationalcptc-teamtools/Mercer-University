#!/usr/bin/env bash
# CyBears: targeted review for possible credentials placed in AD free-text fields.
# Inspired by a recurring CPTC report theme: passwords in user description/comment.
# Authenticated read-only LDAP search only. Does NOT retrieve field contents.
# Output is DNs of potential matches, NOT secrets. Human verification required.
#
# Usage: bash scripts/07_ad_attribute_review.sh scope.txt DC_IP DC_FQDN AD_DOMAIN results_dir
# Requires: an existing Kerberos cache (KRB5CCNAME), ldapsearch, klist, DNS.
# The substring filter below may require an expensive directory-wide search;
# use against a designated DC with explicit permission, not as a default sweep.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
if [[ $# -ne 5 ]]; then
    echo "Usage: bash $0 <scope.txt> <DC_IP> <DC_FQDN> <AD_DOMAIN> <results_dir>" >&2
    exit 2
fi
need python3; need ldapsearch; need timeout; need klist; need getent
SCOPE="$1"; DC_IP="$2"; FQDN="$3"; DOMAIN="${4%.}"; BASE="$5"
# Validate the DNS components; avoid LDAP injection through the domain/base DN.
if [[ ! "$DOMAIN" =~ ^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$ || ! "$FQDN" =~ ^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$ ]]; then
    echo 'Provide valid dotted DNS names for DC_FQDN and AD_DOMAIN.' >&2; exit 2
fi
python3 "$ROOT/lib/scope.py" check-ip "$SCOPE" "$DC_IP" >/dev/null
mapfile -t RESOLVED < <(getent ahostsv4 "$FQDN" | awk '{print $1}' | sort -u)
if [[ ${#RESOLVED[@]} -ne 1 || "${RESOLVED[0]}" != "$DC_IP" ]]; then
    echo "ERROR: $FQDN must resolve only to the permitted DC IP $DC_IP." >&2; exit 1
fi
if [[ -z "${KRB5CCNAME:-}" ]] || ! klist -s; then
    echo 'ERROR: Need an active, authorized Kerberos ticket in KRB5CCNAME.' >&2; exit 1
fi
# Construct a DN solely from validated DNS labels, not operator-supplied LDAP syntax.
BASE_DN="$(python3 - "$DOMAIN" <<'PY'
import sys
print(','.join('DC=' + p for p in sys.argv[1].split('.')))
PY
)"
RUN="$(new_run_dir "$BASE" ad_attribute_review)"
# Search only for suspicious *keywords*, not text values. LDAP returns DNs only.
# Results can be false positives (e.g. 'password policy updated') and misses
# strings lacking these words. Never infer a confirmed secret from a match.
FILTER='(&(objectCategory=person)(objectClass=user)(|(description=*password*)(description=*passwd*)(description=*credential*)(description=*secret*)(comment=*password*)(comment=*passwd*)(comment=*credential*)(comment=*secret*)))'
cat >"$RUN/README.txt" <<META
Time (UTC): $(date -u -Is)
Domain: $DOMAIN
DC: $FQDN ($DC_IP)
Base DN: $BASE_DN
Approach: server-side keyword check on description/comment; only DN is returned.
Results are CANDIDATES, not confirmed passwords. Do not publish sensitive values.
Search may be resource-intensive on a large directory. Confirm RoE and timing.
META
code=0
# -Q suppresses the interactive SASL prompt. -LLL removes LDIF comments,
# -z bounds returned entries, and -o ldif-wrap=no prevents wrapped DNs.
# No attribute values are requested; save only object identifiers.
timeout 90s ldapsearch -LLL -Q -Y GSSAPI -H "ldap://$FQDN" \
    -o ldif-wrap=no -z 200 -b "$BASE_DN" -s sub \
    "$FILTER" dn >"$RUN/candidate_dns.ldif" 2>"$RUN/query_errors.log" || code=$?
printf '%s\n' "$code" >"$RUN/exit_code.txt"
# Do not claim success or treat empty output as proof no exposure exists.
if (( code != 0 )); then
    echo "LDAP query exited $code; see $RUN/query_errors.log" >&2
    exit "$code"
fi
echo "Possible matches: $(grep -ci '^dn:' "$RUN/candidate_dns.ldif" || true)"
echo "Read-only, candidate-only results: $RUN"
