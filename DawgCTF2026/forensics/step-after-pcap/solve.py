#!/usr/bin/env python3
"""
The Step After the PCAP - DawgCTF 2026
LLM-generated forensic log from a PCAP. Timestamps are unreliable ("out of order").
Dst IP is the same for all payload flows (45.76.123.45) — the "LLM forgot to identify where it was going."

512 flow records, 41 have non-empty Payload Fragments.
Sort by record number (= original PCAP order = real chronological order).
Join payloads with underscores.
"""
import re

LOG = "files/network_forensics.log"

with open(LOG) as f:
    text = f.read()

flows = []
for m in re.finditer(r'--- Flow Record #(\d+) ---\n(.*?)----', text, re.DOTALL):
    record_num = int(m.group(1))
    block = m.group(2)
    for line in block.strip().split('\n'):
        if line.strip().startswith('Payload Fragment:'):
            payload = line.split(':', 1)[1].strip()
            if payload != '-':
                flows.append((record_num, payload))
            break

flows.sort(key=lambda x: x[0])
flag = '_'.join(p for _, p in flows)
print(f"[+] FLAG: DawgCTF{{{flag}}}")
