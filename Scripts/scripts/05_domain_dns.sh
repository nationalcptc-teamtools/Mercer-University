#!/usr/bin/env bash
# Domain/DNS discovery against ONE explicitly authorized DNS server.
# Looks up AD DNS SRV service records, SOA, NS, TXT, MX and A records.
# Uses dig @IP so queries go to the selected in-scope DNS server, not public DNS.
# Optional --axfr tests whether the named DNS server permits a zone transfer.
# Usage: bash scripts/05_domain_dns.sh scope.txt DNS_IP domain.local results/lab1 [--axfr]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
if [[ $# -lt 4 || $# -gt 5 ]]; then
    echo "Usage: bash $0 <scope.txt> <dns-ip> <domain> <results_dir> [--axfr]" >&2; exit 2
fi
need python3; need dig; need timeout
SCOPE="$1"; DNS_IP="$2"; DOMAIN="${3%.}"; BASE="$4"; OPT="${5:-}"
[[ -z "$OPT" || "$OPT" == '--axfr' ]] || { echo "Invalid option: $OPT" >&2; exit 2; }
# Only DNS names, not arbitrary dig flags: prevents accidental external queries.
if [[ ! "$DOMAIN" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ || "$DOMAIN" == *..* ]]; then
    echo "Invalid DNS domain name: $DOMAIN" >&2; exit 2
fi
python3 "$ROOT/lib/scope.py" check-ip "$SCOPE" "$DNS_IP" >/dev/null
RUN="$(new_run_dir "$BASE" domain_dns)"
printf 'UTC: %s\nDomain: %s\nDNS server: %s\n\n' "$(date -u -Is)" "$DOMAIN" "$DNS_IP" >"$RUN/query_manifest.txt"
# Each query is a single UDP DNS request, with TCP fallback as dig requires.
# +time=2 +tries=1 prevents repeated hanging lookups if a target drops DNS.
query() {
    local name="$1" type="$2" slug="$3" rc=0
    printf '  %-36s %s\n' "$name" "$type"
    timeout 15s dig "@$DNS_IP" +time=2 +tries=1 +noall +answer \
        "$name" "$type" >"$RUN/${slug}.txt" 2>&1 || rc=$?
    printf '%s\t%s\t%s\t%s\n' "$name" "$type" "$rc" "${slug}.txt" >>"$RUN/query_index.tsv"
}
printf 'query\ttype\texit_code\tfile\n' >"$RUN/query_index.tsv"
query "$DOMAIN" SOA soa
query "$DOMAIN" NS ns
query "$DOMAIN" MX mx
query "$DOMAIN" TXT txt
query "$DOMAIN" A domain_a
query "_ldap._tcp.dc._msdcs.$DOMAIN" SRV domain_controllers
query "_ldap._tcp.$DOMAIN" SRV ldap
query "_kerberos._tcp.$DOMAIN" SRV kerberos_tcp
query "_kerberos._udp.$DOMAIN" SRV kerberos_udp
query "_kpasswd._tcp.$DOMAIN" SRV kpasswd
query "_gc._tcp.$DOMAIN" SRV global_catalog
if [[ "$OPT" == '--axfr' ]]; then
    echo 'Optional AXFR requested: asks DNS server to transfer entire zone.'
    rc=0
    timeout 30s dig "@$DNS_IP" +time=3 +tries=1 "$DOMAIN" AXFR \
        >"$RUN/axfr.txt" 2>&1 || rc=$?
    printf '%s\tAXFR\t%s\taxfr.txt\n' "$DOMAIN" "$rc" >>"$RUN/query_index.tsv"
fi
printf 'DNS evidence: %s\nDo not treat DNS answers as permission to scan newly discovered IPs.\n' "$RUN"
