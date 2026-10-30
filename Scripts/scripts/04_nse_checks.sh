#!/usr/bin/env bash
# Selected Nmap Scripting Engine (NSE) checks for possible misconfigurations.
# Usage: bash scripts/04_nse_checks.sh scope.txt live_hosts.txt results/lab1 [baseline|tls-deep|vuln-safe]
# baseline: explicit allowlist of generally low-impact TLS, HTTP, SSH, SMB checks.
# tls-deep: opt-in intrusive TLS handshake/cipher enumeration.
# vuln-safe: opt-in scripts tagged BOTH 'vuln' and 'safe'; still ACTIVE and logged.
# Neither profile automatically confirms severity or runs exploitation workflows.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
if [[ $# -lt 3 || $# -gt 4 ]]; then
    echo "Usage: bash $0 <scope.txt> <hosts.txt> <results_dir> [baseline|tls-deep|vuln-safe]" >&2; exit 2
fi
need python3; need nmap
SCOPE="$1"; HOSTS="$2"; BASE="$3"; PROFILE="${4:-baseline}"
case "$PROFILE" in
    baseline)
        # Curated scripts; do not use -sC or category 'all' indiscriminately.
        SCRIPTS='http-security-headers,http-cookie-flags,ssl-cert,ssh2-enum-algos,smb2-security-mode,smb-protocols'
        ;;
    tls-deep)
        # SSL cipher enumeration is Nmap-classified *intrusive* and may open
        # many TLS connections. Opt in only when approved and needed.
        SCRIPTS='ssl-enum-ciphers'
        ;;
    vuln-safe)
        # 'vuln' alone can include intrusive/exploit/DoS scripts.
        # This INTERSECTION deliberately removes scripts in high-risk categories.
        SCRIPTS='vuln and safe and not (intrusive or dos or exploit or brute or external)'
        ;;
    *) echo "Unknown NSE profile: $PROFILE" >&2; exit 2 ;;
esac
RUN="$(new_run_dir "$BASE" nse_checks)"
python3 "$ROOT/lib/scope.py" hosts "$SCOPE" "$HOSTS" "$RUN/hosts.validated.txt"
python3 "$ROOT/lib/scope.py" normalize "$SCOPE" "$RUN/targets.txt" "$RUN/excluded.txt" >/dev/null
set_exclusions "$RUN/excluded.txt"
# Inspect what the script selection means on the current Nmap installation.
# Nmap's 'safe' label does NOT mean undetectable or completely risk-free.
printf 'NSE selection: %s\n' "$SCRIPTS" | tee "$RUN/selection.txt"
# -sV identifies which protocol is really present; -Pn targets known hosts.
# Lower packet rate and short script timeout reduce load, not visibility.
nmap -n -Pn -sT -sV --version-light -T2 --max-rate 20 \
    --script-timeout 30s --open \
    -p 22,25,53,80,139,389,443,445,636,993,995,3389,5985,5986,8080,8443 \
    --script "$SCRIPTS" -iL "$RUN/hosts.validated.txt" \
    "${NMAP_EXCLUDES[@]}" -oA "$RUN/nse_${PROFILE}" >"$RUN/scan.log" 2>&1
python3 "$ROOT/lib/scope.py" nse "$SCOPE" "$RUN/nse_${PROFILE}.xml" "$RUN/nse_observations.csv"
echo "Review raw script output: $RUN — script output is not a confirmed finding."
