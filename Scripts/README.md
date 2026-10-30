# CyBears CPTC Starter Toolkit

A **minimal, readable, low-impact** reconnaissance and evidence-collection toolkit inspired by scripts collected from other universities. This is a new implementation, not a copy of their scripts.

These scripts are intended **only for explicitly authorized training labs and permitted CPTC scope**. The actual Rules of Engagement (ROE) and Scope of Work (SOW) always override the sample configuration.

## What is included?

| Script | What it does | What it will not do |
| --- | --- | --- |
| `00_check_tools.sh` | Shows tool availability and versions; saves `tool_versions.txt` | Install tools or change system settings |
| `01_discover_hosts.sh` | Probes approved IPv4 ranges with ICMP, SYN, and ACK; merges live IPs and records discovery methods | Scan ports beyond host-discovery probes, attack credentials |
| `02_scan_ports.sh` | TCP connect/service-version scan of validated live hosts; exports raw Nmap output and `open_ports.csv` | Exploit services or automatically assert vulnerabilities |
| `03_windows_preauth.sh` | Checks for SMB/LDAP on validated hosts; fingerprints SMB and tries anonymous share/user enumeration; saves per-check logs | Password spraying, credential guessing, vulnerability exploitation |

`lib/scope.py` is a small dependency-free helper that verifies every subnet and host list and parses Nmap XML. `lib/common.sh` handles private output permissions and unique run directories.

## Kali prerequisites

Requires **Bash, Python 3, Nmap**; `03_windows_preauth.sh` additionally needs **NetExec (`nxc`)** and `timeout`. The checker script reports missing dependencies, but **does not install anything**. Review package availability and versions on your own Kali installation.

A `fish` interactive shell is fine: invoke scripts with **`bash scripts/<name>.sh ...`** exactly as shown. You do not need to change your shell.

## First-time setup

```bash
# In Kali, from this project's folder:
cp config/scope.example.txt config/scope.txt
nano config/scope.txt     # REPLACE the sample IP range with approved scope
bash scripts/00_check_tools.sh results/lab1
```

If the SOW excludes any IP inside a network, **do not scan the whole network**. List only explicitly allowed IPs or narrower CIDRs in `config/scope.txt`. The starter scripts do not yet implement an exclusion list.

## Run in order

```bash
# 1. Host discovery. Authorize raw probes while keeping output user-owned.
sudo -v
bash scripts/01_discover_hosts.sh config/scope.txt results/lab1

# 2. Scan common TCP ports on the live hosts found above.
bash scripts/02_scan_ports.sh config/scope.txt results/lab1/live_hosts.txt results/lab1 quick

# Optional: full 1-65535 TCP ports (more time/traffic; only when permitted).
# bash scripts/02_scan_ports.sh config/scope.txt results/lab1/live_hosts.txt results/lab1 full

# 3. Basic unauthenticated SMB/LDAP information gathering.
bash scripts/03_windows_preauth.sh config/scope.txt results/lab1/live_hosts.txt results/lab1
```

> Do **not** run the entire script as root (`sudo bash ...`). It explicitly asks you to run `sudo -v` first, then elevates only its individual Nmap discovery probes. Raw XML evidence remains owned by your normal user.

## Evidence layout

Each execution creates a unique UTC-timestamped directory; scripts do not overwrite earlier raw evidence:

```text
results/lab1/
├── tool_versions.txt
├── live_hosts.txt                         # last discovery: convenience COPY
├── discovery/
│   └── 20261028T160000Z_XXXXXX/
│       ├── scope.validated.txt
│       ├── icmp.xml / icmp.log
│       ├── syn.xml / syn.log
│       ├── ack.xml / ack.log
│       ├── live_hosts.txt                 # preserved original results
│       └── discovery_methods.csv
├── ports/
│   └── <timestamp>_XXXXXX/
│       ├── hosts.validated.txt
│       ├── tcp_quick.nmap / .gnmap / .xml
│       ├── scan.log
│       └── open_ports.csv
└── windows_preauth/
    └── <timestamp>_XXXXXX/
        ├── windows_ports.xml / windows_ports.log
        ├── smb_hosts.txt / ldap_hosts.txt
        ├── check_index.tsv
        └── <IP>_<check>.txt
```

### Important limitations

- Host discovery cannot prove that an unresponsive machine is down. Local Ethernet/ARP behavior can also affect which hosts Nmap discovers.
- A service banner is **not proof** of a vulnerability or exact software version.
- Anonymous SMB/LDAP queries may legitimately fail. `Exit status: 0` alone is **not** proof of access or a finding.
- This toolkit does not store credentials or perform authenticated testing. Store collected output securely and only in locations permitted by the competition.
- Before an actual event, validate these scripts against the latest **event-specific rules** and test every enabled scan in a lab.
- Scripts do not yet support IPv6, host exclusions, nonstandard protocols, or coordinated team data storage.

## Attribution and adaptation

Design inspired by Tennessee Tech's discovery script, Cal Poly Pomona's Windows pre-auth checks, and Princess Sumaya's verification/logging practices. If you later incorporate upstream code directly, check its license and retain required copyright notices and attribution.

## Exactly what each script sends over the network

- **`00_check_tools.sh`:** no network traffic. Calls local `command -v` and `--version` commands, then writes a local text report.
- **`01_discover_hosts.sh`:** Nmap host-discovery probes across the addresses in the approved scope file. First requests ICMP echo, then TCP SYN probes to ports 22/80/443/445/3389, then TCP ACK probes to those ports. Nmap may use local link-layer ARP discovery where appropriate. All three raw XML responses are retained and merged by the Python parser. The script does **not** scan all TCP ports.
- **`02_scan_ports.sh`:** TCP **connect** scans and lightweight Nmap service-version probes against the live-host list. The default `quick` profile targets 30 named ports; `full` targets all TCP ports. Output includes Nmap's raw formats, its diagnostic log, and a CSV summary of open ports. No exploit scripts are invoked.
- **`03_windows_preauth.sh`:** TCP connect checks on ports 389 (LDAP) and 445 (SMB), followed by `nxc smb <ip>` fingerprinting and a **single empty-credential** SMB shares query on hosts with 445 open. Hosts with 389 open receive a **single empty-credential** LDAP users query. It never runs module sweeps or tests a wordlist.

The Windows checks can trigger security monitoring and enumerate usernames if anonymous access is allowed. Run them only when the approved rules allow such probes, and never assume that a successful command means a confirmed finding.
