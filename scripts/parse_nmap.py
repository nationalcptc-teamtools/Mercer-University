#!/usr/bin/env python3
import sys, xml.etree.ElementTree as ET, csv
if len(sys.argv) < 3:
    print("Usage: parse_nmap.py <nmap.xml> <output.csv>")
    sys.exit(1)
xmlfile, csvfile = sys.argv[1], sys.argv[2]
root = ET.parse(xmlfile).getroot()
with open(csvfile, 'w', newline='') as out:
    w = csv.writer(out)
    w.writerow(['host','port','protocol','service','state'])
    for host in root.findall('host'):
        addr_el = host.find('address')
        if addr_el is None:
            continue
        addr = addr_el.get('addr')
        for port in host.findall('.//port'):
            p = port.get('portid')
            proto = port.get('protocol')
            state_el = port.find('state')
            state = state_el.get('state') if state_el is not None else ''
            svc_el = port.find('service')
            svc = svc_el.get('name') if svc_el is not None else ''
            w.writerow([addr,p,proto,svc,state])
