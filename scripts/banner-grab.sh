#!/usr/bin/env bash
#Try to capture service banners to fingerprint versions.
#needs nc (netcat) or ncat, timeout
#usage: ./banner-grab.sh open_ports.txt
while read -r line; do
  host=${line%%:*}
  port=${line##*:}
  echo "[+] $host:$port"
  timeout 2 bash -c "echo | nc -nv $host $port" 2>/dev/null | sed -n '1,6p'
done < "${1:-open_ports.txt}"
