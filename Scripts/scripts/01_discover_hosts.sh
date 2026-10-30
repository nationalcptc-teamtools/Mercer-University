#!/usr/bin/env bash
# Find responsive hosts in authorized scope; optional OS fingerprinting.
# Usage: bash scripts/01_discover_hosts.sh config/scope.txt results/lab1 [standard|low-noise] [--os]
# STANDARD: ICMP echo + TCP SYN + TCP ACK discovery.
# LOW-NOISE: only ICMP echo + SYN to fewer ports, rate-limited. Still detectable!
# --os: extra active Nmap OS fingerprinting on discovered hosts (more traffic).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
if [[ $# -lt 2 || $# -gt 4 ]]; then
    echo "Usage: bash $0 <scope.txt> <results_directory> [standard|low-noise] [--os]" >&2
    exit 2
fi
need python3; need nmap; need sudo
if (( EUID == 0 )); then echo 'Run as your normal user; use sudo -v first.' >&2; exit 1; fi
if ! sudo -n true >/dev/null 2>&1; then echo 'Run sudo -v first (only Nmap probes need elevation).' >&2; exit 1; fi
SCOPE="$1"; BASE="$2"
PROFILE='standard'; OS=false
for opt in "${@:3}"; do
    case "$opt" in
        standard|low-noise) PROFILE="$opt" ;;
        --os) OS=true ;;
        *) echo "Unknown option: $opt" >&2; exit 2 ;;
    esac
done
RUN="$(new_run_dir "$BASE" discovery)"
python3 "$ROOT/lib/scope.py" normalize "$SCOPE" "$RUN/targets.txt" "$RUN/excluded.txt"
set_exclusions "$RUN/excluded.txt"
common=(-sn -n -iL "$RUN/targets.txt" "${NMAP_EXCLUDES[@]}")
if [[ "$PROFILE" == 'low-noise' ]]; then
    timing=(-T2 --max-rate 15 --max-retries 1)
else
    timing=(-T3)
fi
run_discovery() {
    local name="$1"; shift
    echo "Discovery method: $name"
    # -oX - writes XML to stdout so raw evidence remains owned by this operator.
    sudo -n nmap "${common[@]}" "${timing[@]}" "$@" -oX - \
        >"$RUN/$name.xml" 2>"$RUN/$name.log"
}
run_discovery icmp -PE
if [[ "$PROFILE" == 'low-noise' ]]; then
    run_discovery syn -PS22,80,443,445
    xmls=("$RUN/icmp.xml" "$RUN/syn.xml")
else
    run_discovery syn -PS22,80,443,445,3389
    run_discovery ack -PA22,80,443,445,3389
    xmls=("$RUN/icmp.xml" "$RUN/syn.xml" "$RUN/ack.xml")
fi
python3 "$ROOT/lib/scope.py" discovery "$SCOPE" \
    "$RUN/live_hosts.txt" "$RUN/discovery_methods.csv" "${xmls[@]}"
cp "$RUN/live_hosts.txt" "$BASE/live_hosts.txt"
if [[ "$OS" == true ]]; then
    if [[ -s "$RUN/live_hosts.txt" ]]; then
        echo 'OS fingerprinting: additional TCP/IP probes; accuracy depends on open/closed ports.'
        # -O sends OS probes and --osscan-limit skips poor detection candidates.
        # A high-numbered port is included to improve chance of a closed port.
        sudo -n nmap -n -Pn -sS -O --osscan-limit --max-os-tries 1 \
            "${timing[@]}" -p 21,22,53,80,88,135,139,389,443,445,3389,5985,65000 \
            -iL "$RUN/live_hosts.txt" "${NMAP_EXCLUDES[@]}" \
            -oX - >"$RUN/os_fingerprint.xml" 2>"$RUN/os_fingerprint.log"
        python3 "$ROOT/lib/scope.py" os-inventory "$SCOPE" "$RUN/live_hosts.txt" \
            "$RUN/os_fingerprint.xml" "$RUN/hosts_inventory.csv"
        cp "$RUN/hosts_inventory.csv" "$BASE/hosts_inventory.csv"
    else
        echo 'No responsive hosts; skipping OS fingerprints.'
    fi
fi
printf '\nSaved run: %s\nLive hosts: %s/live_hosts.txt\n' "$RUN" "$BASE"
