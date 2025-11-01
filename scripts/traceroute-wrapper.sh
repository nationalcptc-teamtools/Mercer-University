#!/usr/bin/env bash
#Get path information to hosts (internal routing can reveal segmentation).
#usage: ./traceroute-wrapper.sh 10.10.10.5 10.10.10.6
mkdir -p traceroutes
for host in "$@"; do
  echo "[+] traceroute $host"
  traceroute -n "$host" > traceroutes/"${host}_tr.txt"
done
