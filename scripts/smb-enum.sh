#!/usr/bin/env bash
#Run enum4linux, rpcclient, and targeted nmap SMB scripts. Pass results to Windows team.
#enum4linux, rpcclient (samba-client), nmap
#usage: ./smb-enum.sh 10.10.10.12
TARGET=$1
OUTDIR=${2:-smb_output}
mkdir -p "$OUTDIR"
echo "[+] enum4linux -a $TARGET"
enum4linux -a "$TARGET" > "$OUTDIR/${TARGET}_enum4linux.txt"
echo "[+] rpcclient enumdomusers"
rpcclient -U "" "$TARGET" -c "enumdomusers" > "$OUTDIR/${TARGET}_rpcclient_users.txt" 2>/dev/null || true
echo "[+] nmap smb scripts"
nmap -p445 --script smb-enum-users,smb-enum-shares -oA "$OUTDIR/${TARGET}_nmap_smb" "$TARGET"
