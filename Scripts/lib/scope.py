#!/usr/bin/env python3
"""Validate authorized scope and turn Nmap XML into reviewable CSV files.

Scope syntax (one entry per line): IPv4, CIDR, inclusive start-end IPv4 range,
or the same entry prefixed with ! to EXCLUDE it. Comments start with #.
This helper is deliberately strict: out-of-scope targets abort the script.
"""
import argparse
import csv
import ipaddress
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def fail(message):
    raise ValueError(message)


def entries(path):
    with open(path, encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, 1):
            value = raw.split('#', 1)[0].strip()
            if value:
                yield line_no, value


def parse_entry(value, source):
    """Convert inclusive start-end ranges to exact CIDRs; never round outward."""
    if '-' in value:
        parts = value.split('-')
        if len(parts) != 2:
            fail(f"{source}: invalid start-end range {value!r}")
        try:
            first, last = (ipaddress.IPv4Address(part.strip()) for part in parts)
        except ipaddress.AddressValueError as exc:
            fail(f"{source}: {exc}")
        if int(last) < int(first):
            fail(f"{source}: range end precedes start: {value!r}")
        if int(last) - int(first) + 1 > 65536:
            fail(f"{source}: ranges larger than 65,536 addresses are refused")
        return list(ipaddress.summarize_address_range(first, last))
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        fail(f"{source}: invalid scope entry {value!r}: {exc}")
    if net.version != 4:
        fail(f"{source}: IPv6 is not supported")
    if net.prefixlen < 16:
        fail(f"{source}: scope broader than /16 is refused: {value!r}")
    return [net]


class Scope:
    def __init__(self, includes, excludes):
        self.includes = includes
        self.excludes = excludes

    def allows(self, ip):
        return any(ip in n for n in self.includes) and not any(ip in n for n in self.excludes)


def read_scope(path):
    includes, excludes = [], []
    for line_no, value in entries(path):
        excluded = value.startswith('!')
        value = value[1:].strip() if excluded else value
        nets = parse_entry(value, f"{path}:{line_no}")
        for n in nets:
            if n.is_multicast or n.is_loopback or n.is_unspecified:
                fail(f"{path}:{line_no}: special-purpose address range is not accepted")
            target = excludes if excluded else includes
            if n not in target:
                target.append(n)
    if not includes:
        fail(f"{path}: no permitted IPs/CIDRs/ranges")
    return Scope(includes, excludes)


def write_lines(path, values):
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(''.join(f'{v}\n' for v in values), encoding='utf-8')


def read_hosts(path, scope):
    hosts = set()
    for line_no, value in entries(path):
        try:
            ip = ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError:
            fail(f"{path}:{line_no}: expected one IPv4 address, got {value!r}")
        if not scope.allows(ip):
            fail(f"{path}:{line_no}: {ip} is outside approved scope or excluded")
        hosts.add(ip)
    if not hosts:
        fail(f"{path}: empty in-scope host list")
    return sorted(hosts)


def xml_hosts(path):
    for host in ET.parse(path).getroot().findall('host'):
        ip_text = next((n.get('addr') for n in host.findall('address')
                        if n.get('addrtype') == 'ipv4'), None)
        if ip_text:
            yield host, ipaddress.IPv4Address(ip_text)


def checked_host_rows(xml_file, scope):
    for host, ip in xml_hosts(xml_file):
        if not scope.allows(ip):
            fail(f"Out-of-scope result in {xml_file}: {ip}")
        yield host, ip


def discovery(scope, xmls, host_file, method_file):
    methods = {}
    for xml in xmls:
        for host, ip in checked_host_rows(xml, scope):
            status = host.find('status')
            if status is not None and status.get('state') == 'up':
                methods.setdefault(ip, set()).add(Path(xml).stem)
    ips = sorted(methods)
    write_lines(host_file, ips)
    with open(method_file, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['ip', 'discovery_methods'])
        for ip in ips:
            w.writerow([str(ip), ';'.join(sorted(methods[ip]))])
    print(f"Discovered {len(ips)} permitted host(s): {host_file}")


def csv_safe(value):
    text = str(value)
    return "'" + text if text.lstrip().startswith(('=', '+', '-', '@')) else text


def ports(scope, xml, output):
    count = 0
    with open(output, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['ip', 'protocol', 'port', 'state', 'service', 'product', 'version'])
        for host, ip in checked_host_rows(xml, scope):
            for port in host.findall('./ports/port'):
                status = port.find('state')
                if status is None or status.get('state') != 'open':
                    continue
                service = port.find('service')
                data = service.attrib if service is not None else {}
                w.writerow([csv_safe(v) for v in (
                    ip, port.get('protocol', ''), port.get('portid', ''),
                    'open', data.get('name', ''), data.get('product', ''),
                    data.get('version', ''))])
                count += 1
    print(f"Saved {count} open TCP service(s): {output}")


def service_hosts(scope, xml, port, output):
    found = set()
    for host, ip in checked_host_rows(xml, scope):
        for entry in host.findall('./ports/port'):
            state = entry.find('state')
            if entry.get('portid') == str(port) and state is not None and state.get('state') == 'open':
                found.add(ip)
    write_lines(output, sorted(found))
    print(f"TCP {port}: {len(found)} host(s)")


def os_inventory(scope, known_hosts, os_xml, output):
    """OS fingerprint is a hypothesis, not confirmation; preserve Nmap accuracy."""
    known = read_hosts(known_hosts, scope)
    results = {}
    for host, ip in checked_host_rows(os_xml, scope):
        matches = host.findall('./os/osmatch')
        if matches:
            top = max(matches, key=lambda item: int(item.get('accuracy', '0')))
            results[ip] = (top.get('name', 'unknown'), top.get('accuracy', ''))
    with open(output, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['ip', 'os_guess', 'nmap_match_percent', 'note'])
        for ip in known:
            guess, accuracy = results.get(ip, ('Unknown', ''))
            w.writerow([str(ip), csv_safe(guess), accuracy,
                        'Unverified network fingerprint' if accuracy else 'No confident OS fingerprint'])
    print(f"OS inventory: {output} ({len(results)}/{len(known)} hosts with matches)")


def nse_observations(scope, xml, output):
    """Preserve script output for manual investigation; do not invent severity."""
    count = 0
    with open(output, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['ip', 'port', 'script', 'observation', 'status'])
        for host, ip in checked_host_rows(xml, scope):
            for entry in host.findall('./hostscript/script'):
                w.writerow([ip, '', csv_safe(entry.get('id', '')),
                            csv_safe(entry.get('output', '')), 'review_required'])
                count += 1
            for port in host.findall('./ports/port'):
                for entry in port.findall('script'):
                    w.writerow([ip, port.get('portid', ''), csv_safe(entry.get('id', '')),
                                csv_safe(entry.get('output', '')), 'review_required'])
                    count += 1
    print(f"Saved {count} NSE observation(s): {output}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest='action', required=True)
    p = sub.add_parser('normalize')
    p.add_argument('scope'); p.add_argument('includes'); p.add_argument('excludes', nargs='?')
    p = sub.add_parser('hosts')
    p.add_argument('scope'); p.add_argument('host_input'); p.add_argument('output')
    p = sub.add_parser('check-ip')
    p.add_argument('scope'); p.add_argument('ip')
    p = sub.add_parser('discovery')
    p.add_argument('scope'); p.add_argument('host_output'); p.add_argument('methods_output'); p.add_argument('xml', nargs='+')
    p = sub.add_parser('ports')
    p.add_argument('scope'); p.add_argument('xml'); p.add_argument('output')
    p = sub.add_parser('service-hosts')
    p.add_argument('scope'); p.add_argument('xml'); p.add_argument('port', type=int); p.add_argument('output')
    p = sub.add_parser('os-inventory')
    p.add_argument('scope'); p.add_argument('host_list'); p.add_argument('xml'); p.add_argument('output')
    p = sub.add_parser('nse')
    p.add_argument('scope'); p.add_argument('xml'); p.add_argument('output')
    a = ap.parse_args()
    try:
        scope = read_scope(a.scope)
        if a.action == 'normalize':
            write_lines(a.includes, scope.includes)
            if a.excludes:
                write_lines(a.excludes, scope.excludes)
            print(f"Allowed target entries: {len(scope.includes)}; exclusions: {len(scope.excludes)}")
        elif a.action == 'hosts':
            write_lines(a.output, read_hosts(a.host_input, scope))
        elif a.action == 'check-ip':
            ip = ipaddress.IPv4Address(a.ip)
            if not scope.allows(ip):
                fail(f"{ip} is excluded or out of scope")
            print(f"Authorized: {ip}")
        elif a.action == 'discovery':
            discovery(scope, a.xml, a.host_output, a.methods_output)
        elif a.action == 'ports':
            ports(scope, a.xml, a.output)
        elif a.action == 'service-hosts':
            service_hosts(scope, a.xml, a.port, a.output)
        elif a.action == 'os-inventory':
            os_inventory(scope, a.host_list, a.xml, a.output)
        elif a.action == 'nse':
            nse_observations(scope, a.xml, a.output)
    except (OSError, ValueError, ET.ParseError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
