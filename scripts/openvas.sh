#!/usr/bin/env bash
# openvas.sh - install, set up, and start OpenVAS (GVM) on Kali
set -e

[ "$EUID" -eq 0 ] || { echo "Run with sudo"; exit 1; }

apt update
apt install -y gvm
gvm-setup          # slow: builds the DB and syncs feeds. Prints the admin password at the end
gvm-check-setup    # sanity check
gvm-start

echo "OpenVAS is up: https://127.0.0.1:9392 (user: admin)"
