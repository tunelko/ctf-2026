# Dead Drop — VishwaCTF 2026

| Field | Value |
|-------|-------|
| **CTF** | VishwaCTF 2026 |
| **Category** | Forensics |
| **Challenge** | Dead Drop |
| **Flag** | `VishwaCTF{dns_tunnel_r3v34l3d_by_ttl_and_timing}` |
| **Files** | `dead_drop.pcapng` |

## TL;DR

DNS exfiltration via Base32-encoded subdomains to `*.r3s.io`, with one decoy label containing an invalid character. Remove the decoy, concatenate, Base32-decode → flag. Final UDP packet uses an anomalous TTL (79 vs standard 64) as a covert completion signal.

## Analysis

### Reconnaissance

The PCAP contains 68 frames captured from workstation `10.0.1.114`:

| Protocol | Frames | Purpose |
|----------|--------|---------|
| DNS | 58 | Queries + responses (exfil channel + cover traffic) |
| UDP (raw) | 1 | Final signaling packet |
| TCP/TLS | 9 | Legitimate HTTPS noise |

### DNS Traffic Breakdown

Two types of DNS queries originate from the workstation:

**Cover traffic** — legitimate domains to blend in:
```
google.com, outlook.office365.com, teams.microsoft.com,
login.microsoftonline.com, cdn.teams.microsoft.com,
www.google.com, www.youtube.com, fonts.googleapis.com,
accounts.google.com, update.googleapis.com,
safebrowsing.googleapis.com, clients2.google.com
```

**Exfiltration channel** — subdomains of `r3s.io`:
```
KZUX.r3s.io        4ZLM.r3s.io
G2DX.r3s.io        L5ZD.r3s.io
MFBV.r3s.io        G5RT.r3s.io
IRT3.r3s.io        GRWD.r3s.io
MRXH.r3s.io        GZC7.r3s.io
GX3U.r3s.io        MJ4V.r3s.io
OVXG.r3s.io        65DU.r3s.io
C3X8EMJQ.r3s.io    NRPW.r3s.io
                    C3TEL52GS3LJNZTX2.r3s.io
```

Sequential source ports (`49200`–`49216`) confirm these are a single ordered exfil stream.

## Vulnerability / Technique

**DNS tunneling** (T1071.004 — Application Layer Protocol: DNS) with Base32 encoding in subdomain labels.

## Exploitation Steps

### Step 1 — Extract exfil labels

Filter DNS queries to `r3s.io` and extract subdomain labels:

```bash
tshark -r dead_drop.pcapng -T fields -e dns.qry.name \
  -Y "dns.flags.response == 0 and dns.qry.name contains r3s.io"
```

### Step 2 — Identify and remove decoy

The label `C3X8EMJQ` contains the character `8`, which is **not valid Base32** (Base32 alphabet: `A-Z`, `2-7`). This is a decoy label inserted to frustrate automated decoding.

### Step 3 — Decode payload

Concatenate the 16 valid labels and Base32-decode:

```python
import base64

labels = [
    'KZUX', 'G2DX', 'MFBV', 'IRT3', 'MRXH', 'GX3U', 'OVXG',
    '4ZLM', 'L5ZD', 'G5RT', 'GRWD', 'GZC7',
    'MJ4V', '65DU', 'NRPW', 'C3TEL52GS3LJNZTX2'
]
# Note: C3X8EMJQ excluded (invalid base32 char '8')

combined = ''.join(labels)
padded = combined + '=' * (-len(combined) % 8)
flag = base64.b32decode(padded).decode()
print(flag)
# VishwaCTF{dns_tunnel_r3v34l3d_by_ttl_and_timing}
```

### Step 4 — Identify signaling mechanism

The final packet (frame 68) is a raw UDP packet, not DNS:

| Field | Value | Note |
|-------|-------|------|
| Src | `10.0.1.114:49227` | Workstation |
| Dst | `185.220.101.47:53412` | External (known Tor exit node range) |
| Data | `\x00\x00OKOKOKOK` | Confirmation payload |
| **TTL** | **79** | **Anomalous** — all other packets use TTL 64 |

Every other packet from the workstation uses TTL 64 (Linux default). The TTL of 79 is the **covert signaling mechanism** — the attacker signals exfiltration completion through IP header metadata, not the packet body. This is confirmed by the flag itself: `_by_ttl_and_timing`.

## Key Takeaways

1. **DNS exfil detection**: Watch for high-entropy subdomain labels, especially to uncommon TLDs, with sequential source ports
2. **Decoy/noise injection**: Attackers insert invalid chunks to break naive automated decoders
3. **TTL covert channels**: IP TTL field can carry out-of-band signals — anomalous TTL values in otherwise uniform traffic are a strong IOC
4. **Interleaving with legit traffic**: Exfil queries mixed with real DNS to evade volume-based detection

## Files

```
Dead Drop/
├── dead_drop.pcapng   # Original PCAP
├── flag.txt           # Captured flag
└── WRITEUP.md         # This file
```
