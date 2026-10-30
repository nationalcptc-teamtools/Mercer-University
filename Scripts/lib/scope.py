#!/usr/bin/env python3
"""Shared, dependency-free scope validation and Nmap XML parsers.

All scripts call this helper rather than trying to parse IP ranges with grep.
Every hosts file is checked against the *explicit* approved scope file.
"""

import argparse
import csv
import ipaddress
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def fail(message):
    raise ValueError(message)


def source_lines(path):
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            entry = line.split("#", 1)[0].strip()
            if entry:
                yield number, entry


def read_scope(path):
    """Require explicit IPv4 CIDRs/IPs; reject unexpectedly broad targets."""
    networks = []
    for number, item in source_lines(path):
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            fail(f"{path}:{number}: invalid scope entry {item!r}: {exc}")
        if network.version != 4:
            fail(f"{path}:{number}: IPv6 is not supported by these starter scripts")
        if network.prefixlen < 16:
            fail(f"{path}:{number}: {item!r} is broader than /16; split it into approved ranges")
        if network.is_multicast or network.is_loopback or network.is_unspecified:
            fail(f"{path}:{number}: special-purpose IP space is not an assessment scope")
        if network not in networks:
            networks.append(network)
    if not networks:
        fail(f"{path}: no scope entries; populate it with approved target IPs/CIDRs")
    return networks


def write_lines(path, values):
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(f"{value}\n" for value in values), encoding="utf-8")


def read_hosts(path, networks):
    hosts = set()
    for number, item in source_lines(path):
        try:
            ip = ipaddress.ip_address(item)
        except ValueError:
            fail(f"{path}:{number}: expected one IPv4 host per line, got {item!r}")
        if ip.version != 4 or not any(ip in net for net in networks):
            fail(f"{path}:{number}: {ip} is OUTSIDE the approved scope")
        hosts.add(ip)
    if not hosts:
        fail(f"{path}: no in-scope hosts to scan")
    return sorted(hosts)


def xml_hosts(path):
    """Read the Nmap XML output, not screen text or unstable grep columns."""
    root = ET.parse(path).getroot()
    for host in root.findall("host"):
        address = next(
            (node.get("addr") for node in host.findall("address")
             if node.get("addrtype") == "ipv4"), None
        )
        if address:
            yield host, ipaddress.ip_address(address)


def summarize_discovery(scopes, filenames, host_output, provenance_csv):
    by_ip = {}
    for filename in filenames:
        method = Path(filename).stem
        for host, ip in xml_hosts(filename):
            if host.find("status") is None or host.find("status").get("state") != "up":
                continue
            if not any(ip in net for net in scopes):
                fail(f"Unexpected out-of-scope discovery result: {ip}")
            by_ip.setdefault(ip, set()).add(method)
    ordered = sorted(by_ip)
    write_lines(host_output, ordered)
    with open(provenance_csv, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["ip", "discovery_methods"])
        for ip in ordered:
            writer.writerow([str(ip), ";".join(sorted(by_ip[ip]))])
    print(f"Discovered {len(ordered)} in-scope live host(s): {host_output}")


def csv_text(value):
    """Avoid spreadsheet formula execution from untrusted service banners."""
    text = str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def summarize_ports(xml_file, csv_file, scopes):
    with open(csv_file, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["ip", "protocol", "port", "state", "service", "product", "version"])
        rows = 0
        for host, ip in xml_hosts(xml_file):
            if not any(ip in net for net in scopes):
                fail(f"Unexpected out-of-scope scan result: {ip}")
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port.find("service")
                data = service.attrib if service is not None else {}
                writer.writerow([csv_text(value) for value in [
                    str(ip), port.get("protocol", ""), port.get("portid", ""),
                    "open", data.get("name", ""), data.get("product", ""),
                    data.get("version", ""),
                ]])
                rows += 1
    print(f"Recorded {rows} open-port row(s): {csv_file}")


def service_hosts(xml_file, port, output, scopes):
    candidates = set()
    for host, ip in xml_hosts(xml_file):
        if not any(ip in net for net in scopes):
            fail(f"Unexpected out-of-scope scan result: {ip}")
        for item in host.findall("./ports/port"):
            state = item.find("state")
            if item.get("portid") == str(port) and state is not None and state.get("state") == "open":
                candidates.add(ip)
    write_lines(output, sorted(candidates))
    print(f"Port {port}: {len(candidates)} host(s)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    norm = sub.add_parser("normalize", help="validate the scope and write Nmap-compatible targets")
    norm.add_argument("scope")
    norm.add_argument("output")
    hosts = sub.add_parser("hosts", help="verify and deduplicate a host list against scope")
    hosts.add_argument("scope")
    hosts.add_argument("input")
    hosts.add_argument("output")
    discovery = sub.add_parser("discovery", help="merge host discovery XML files")
    discovery.add_argument("scope")
    discovery.add_argument("hosts_output")
    discovery.add_argument("methods_csv")
    discovery.add_argument("xml", nargs="+")
    ports = sub.add_parser("ports", help="extract open ports from Nmap XML to CSV")
    ports.add_argument("scope")
    ports.add_argument("xml")
    ports.add_argument("csv")
    service = sub.add_parser("service-hosts", help="extract hosts with a particular open TCP port")
    service.add_argument("scope")
    service.add_argument("xml")
    service.add_argument("port", type=int)
    service.add_argument("output")
    args = parser.parse_args()
    try:
        scopes = read_scope(args.scope)
        if args.command == "normalize":
            write_lines(args.output, scopes)
            print(f"Approved scope: {', '.join(str(x) for x in scopes)}")
        elif args.command == "hosts":
            write_lines(args.output, read_hosts(args.input, scopes))
        elif args.command == "discovery":
            summarize_discovery(scopes, args.xml, args.hosts_output, args.methods_csv)
        elif args.command == "ports":
            summarize_ports(args.xml, args.csv, scopes)
        elif args.command == "service-hosts":
            service_hosts(args.xml, args.port, args.output, scopes)
    except (OSError, ValueError, ET.ParseError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
