#!/usr/bin/env bash
# Shared helpers; other scripts source this file rather than executing it.
need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'ERROR: Missing program: %s\n' "$1" >&2
        exit 1
    fi
}
# Files may contain hostnames, usernames, and sensitive configuration data.
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
new_run_dir() {
    local parent="$1" kind="$2" out
    mkdir -p "$parent/$kind"
    out="$(mktemp -d "$parent/$kind/$(date -u +%Y%m%dT%H%M%SZ)_XXXXXX")"
    printf '%s\n' "$out"
}
# Generate a Nmap exclusion argument only when exclusions exist.
# This prevents scope.txt's !ranges from being probed at all.
set_exclusions() {
    local excluded_file="$1"
    NMAP_EXCLUDES=()
    if [[ -s "$excluded_file" ]]; then
        NMAP_EXCLUDES=(--excludefile "$excluded_file")
    fi
}
