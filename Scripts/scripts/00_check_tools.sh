#!/usr/bin/env bash
# CyBears CPTC: local dependency check. Never touches target networks.
# Default: report present/missing tools and suggested packages only.
# Optional: --install-core prompts before installing a small, reviewed Kali toolset.
# Usage: bash scripts/00_check_tools.sh [results_dir] [--install-core]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
BASE="$ROOT/results/lab1"; INSTALL=false
for arg in "$@"; do
    case "$arg" in
        --install-core) INSTALL=true ;;
        -h|--help) echo "Usage: bash $0 [results_dir] [--install-core]"; exit 0 ;;
        -*) echo "Unknown option: $arg" >&2; exit 2 ;;
        *) BASE="$arg" ;;
    esac
done
# Only these well-known packages can be installed via this script.
# Advanced assessment tools are suggestions, not automatic downloads.
CORE_PKGS=(python3 nmap netexec dnsutils ldap-utils krb5-user jq)
if [[ "$INSTALL" == true ]]; then
    if (( EUID == 0 )); then echo 'Use a normal Kali account with sudo, not root.' >&2; exit 1; fi
    need sudo; need apt-get
    printf 'Install the following Kali/Debian packages?\n  %s\n' "${CORE_PKGS[*]}"
    printf 'This modifies Kali and may download packages. Type INSTALL to proceed: '
    read -r confirmation
    [[ "$confirmation" == 'INSTALL' ]] || { echo 'Installation cancelled.'; exit 1; }
    sudo apt-get update
    sudo apt-get install --no-install-recommends "${CORE_PKGS[@]}"
fi
mkdir -p "$BASE"
LOG="$BASE/tool_versions.txt"
{
    printf 'CyBears local tool inventory (UTC): %s\n' "$(date -u -Is)"
    printf 'No external target traffic from this script.\n\n'
    printf 'CORE TOOLS — required by one or more scripts:\n'
    for tool in bash python3 nmap nxc sudo timeout dig ldapsearch kinit klist getent jq; do
        if command -v "$tool" >/dev/null 2>&1; then
            printf '[FOUND]   %-18s %s\n' "$tool" "$(command -v "$tool")"
        else
            printf '[MISSING] %-18s\n' "$tool"
        fi
    done
    printf '\nOPTIONAL TOOLS — consider per role and SOW; do not install indiscriminately:\n'
    # Discovery, AD mapping, web assessment, TLS review and finding validation.
    for tool in smbclient rpcclient enum4linux-ng certipy certipy-ad bloodhound-python rusthound-ce ffuf feroxbuster whatweb nikto nuclei searchsploit sslscan ssh-audit curl openssl git sqlmap burpsuite aws az; do
        if command -v "$tool" >/dev/null 2>&1; then
            printf '[FOUND]   %-18s %s\n' "$tool" "$(command -v "$tool")"
        else
            printf '[OPTIONAL] %-18s\n' "$tool"
        fi
    done
    printf '\nNotes: some optional tools may use different executable names across Kali releases.\n'
    printf 'A missing executable is not always a missing package. Install advanced tools manually after approval.\n'
    printf '\nVersion snapshots:\n'
    bash --version | head -n 1
    python3 --version
    if command -v nmap >/dev/null 2>&1; then nmap --version | head -n 1; fi
    if command -v nxc >/dev/null 2>&1; then nxc --version 2>&1 | head -n 1 || true; fi
    printf '\nCore install (explicit opt-in only): bash scripts/00_check_tools.sh %s --install-core\n' "$BASE"
} | tee "$LOG"
echo "Saved local inventory: $LOG"
