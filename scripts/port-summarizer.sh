#!/usr/bin/env bash
#Produce quick counts of open services/ports and host summaries. Useful for prioritization.
#needs awk, sed, and sort
#usage: ./port-summarizer.sh nmap_scan.gnmap
GNMAP=$1
if [[ -z "$GNMAP" ]]; then echo "Usage: $0 file.gnmap"; exit 1; fi
awk -F'Host: ' '/^Host: / {split($2,a," \\("); host=a[1]; match($0,/Ports: (.*)/,m); if (m[1]) print host "\t" m[1] }' "$GNMAP" \
  | sed 's/,/\\n/g' | sed 's/\\/open//g' | awk -F'/' '{print $1}' | sort | uniq -c | sort -nr
