#!/usr/bin/env bash
# Small shared helpers for the CyBears scripts. This file is sourced, not run.

# Refuse to continue when an essential program is missing.
need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'ERROR: Required program is missing: %s\n' "$1" >&2
        exit 1
    fi
}

# Keep results private to the operator by default: logs may contain usernames.
umask 077

# The root directory is computed relative to this file, not the caller's shell.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

# One folder per execution. Prior assessment evidence is never overwritten.
new_run_dir() {
    local parent="$1" kind="$2" out
    mkdir -p "$parent/$kind"
    out="$(mktemp -d "$parent/$kind/$(date -u +%Y%m%dT%H%M%SZ)_XXXXXX")"
    printf '%s\n' "$out"
}
