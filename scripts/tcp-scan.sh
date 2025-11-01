#!/usr/bin/env bash
# tcp-scan.sh - quick tcp discovery and service/version scan
# Usage: ./tcp-scan.sh targets.txt [outdir]
#Batch nmap scans for hosts listed in a file; does a quick top-ports scan then a deeper service/version scan.
TARGETS=${1:-targets.txt}
OUTDIR=${2:-./nmap}
mkdir -p "$OUTDIR"
while read -r host; do
  [[ -z "$host" || "$host" =~ ^# ]] && continue
  echo "[+] Quick top-100 ports for $host"
  nmap -sS -Pn --top-ports 100 -oA "$OUTDIR/${host}_top100" "$host"
  echo "[+] Service/version scan (focused) for $host"
  nmap -sS -sV -Pn --top-ports 100 -oA "$OUTDIR/${host}_sv" "$host"
done < "$TARGETS"
