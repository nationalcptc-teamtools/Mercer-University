#!/usr/bin/env bash
# Purpose: verify the local Kali toolchain before competition day.
# This script does NOT install, download, or change security settings.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

OUT_BASE="${1:-$ROOT/results/lab1}"
mkdir -p "$OUT_BASE"
LOG="$OUT_BASE/tool_versions.txt"

{
    printf 'CyBears local tool check (UTC): %s\n\n' "$(date -u -Is)"
    for command in bash python3 nmap nxc timeout sha256sum; do
        if command -v "$command" >/dev/null 2>&1; then
            printf '[FOUND]   %-10s %s\n' "$command" "$(command -v "$command")"
        else
            printf '[MISSING] %-10s\n' "$command"
        fi
    done
    printf '\nVersions (to help reproduce teammates\x27 results):\n'
    bash --version | head -n 1
    python3 --version
    if command -v nmap >/dev/null 2>&1; then nmap --version | head -n 1; fi
    if command -v nxc >/dev/null 2>&1; then nxc --version 2>&1 | head -n 1; fi
} | tee "$LOG"

printf '\nVersion log saved: %s\n' "$LOG"
printf 'If a tool is missing, install/verify it in your lab BEFORE an engagement.\n'
