#!/usr/bin/env python3
"""
I love Bacon! - DawgCTF 2026
DNS exfiltration: base32-encoded subdomains under .dawg.cwa.sec
Flag hidden in queries that decode to fully printable ASCII.
1000 queries, only 3 contain 100% printable data → flag fragments.
"""
import subprocess, base64

PCAP = "files/dns_c2.pcap"

# Extract DNS query names (requests only) in packet order
result = subprocess.run(
    ['tshark', '-r', PCAP, '-T', 'fields', '-e', 'dns.qry.name',
     '-Y', 'dns.flags.response == 0'],
    capture_output=True, text=True
)
queries = [line.strip().replace('.dawg.cwa.sec', '')
           for line in result.stdout.strip().split('\n') if line.strip()]

# Base32 decode each query; keep only fully printable ASCII results
flag_parts = []
for q in queries:
    padded = q + '=' * ((8 - len(q) % 8) % 8)
    try:
        d = base64.b32decode(padded)
        if all(32 <= b < 127 for b in d):
            flag_parts.append(d.decode('ascii'))
    except:
        pass

flag = ''.join(flag_parts)
print(f"[+] FLAG: {flag}")
