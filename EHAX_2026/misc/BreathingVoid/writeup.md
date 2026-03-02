# BreathingVoid

**Category:** MISC
**Flag:** `EH4X{pc@p5_@re_of+en_mo5+1y_noi5e}`

## Description

> 1GB of dead vacuum. Can you find any life.

## TL;DR

A 1.1GB pcapng file is a merge of three pcaps: padding noise, Metasploit decoy traffic, and a covert timing channel. The flag is encoded in inter-packet delays of 272 identical HTTP requests on a separate network interface: 100ms delay = bit 1, 10ms delay = bit 0.

## Analysis

### File Structure

The pcapng file header reveals it was created by `Mergecap (Wireshark) 4.6.3` and contains a comment listing the three source files:

```
File created by merging:
File1: massive.pcap
File2: decoy_trap.pcap
File3: covert_timing_2.pcap
```

The file contains **4,198,284 packets** across **3 network interfaces**:

| Interface | Link Type | Packets | Purpose |
|-----------|-----------|---------|---------|
| 0 | Ethernet (1) | 4,198,011 | Padding + Decoy traffic |
| 1 | Raw IPv4 (228) | 1 | Sync/reference packet |
| 2 | Raw IPv4 (228) | 272 | **Covert timing channel** |

### Decoy Analysis (Interface 0)

Interface 0 contains two types of traffic designed to waste time:

1. **massive.pcap (~2M packets)**: Identical TCP packets between `192.168.202.83` and `192.168.206.44` — pure padding ("dead vacuum").

2. **decoy_trap.pcap**: Real Metasploit/Armitage traffic from a March 2012 CCDC exercise, including:
   - Armitage RPC on port 55554 (Java serialized `sleep.runtime.Scalar` objects)
   - Meterpreter sessions on ports 8080, 4545
   - PostgreSQL session polling on port 5432
   - TLS-encrypted C2 on port 443
   - A fake flag `EHAX{suck_my_dick}` embedded as a prompt injection trap

### Covert Timing Channel (Interface 2)

The 272 packets on interface 2 are **completely identical** HTTP GET requests:

```http
GET / HTTP/1.1
Host: ghost.local
User-Agent: Chronos-Agent/v0.01-0.10
```

Key observations:
- **All 272 packets have identical content** — the data is NOT in the packet payload
- The `User-Agent: Chronos-Agent/v0.01-0.10` hints at the encoding scheme: version numbers `0.01` and `0.10` correspond to the two timing values (10ms and 100ms)
- Source: `10.10.10.50` → Destination: `10.10.10.200` (port 1337 → port 80)
- Total duration: ~15.67 seconds

### Timing Decode

Inter-packet delays follow a strict binary pattern:
- **10ms (10,000 μs) = bit 0**
- **100ms (100,000 μs) = bit 1**

No other delay values exist — every single delta is exactly one of these two values.

The 271 timing deltas produce 271 bits. Prepending a single `0` bit (aligning to the reference packet from interface 1) gives 272 bits = 34 bytes, which decodes directly to ASCII:

```
EH4X{pc@p5_@re_of+en_mo5+1y_noi5e}
```

(Leet-speak for "pcaps are often mostly noise")

## Solution

### Prerequisites

- Python 3 (standard library only)
- The challenge pcap file `Breathing_Void.pcap`

### Steps

1. Parse the pcapng file and identify the 3 network interfaces
2. Extract the 272 packets from interface 2 (Raw IPv4, link_type=228)
3. Calculate the 271 inter-packet timing deltas
4. Classify each delta: ≥50ms → bit 1, <50ms → bit 0
5. Prepend a `0` bit for byte alignment
6. Convert the 272 bits to 34 bytes (MSB first)
7. Read the ASCII flag

### Solve Script

```python
#!/usr/bin/env python3
# solve.py — BreathingVoid solver
# Usage: python3 solve.py [PCAP_FILE]

import struct, sys

def solve(pcap_file="Breathing_Void.pcap"):
    f = open(pcap_file, 'rb')
    f.read(4)
    block_len = struct.unpack('<I', f.read(4))[0]
    f.seek(block_len)
    for i in range(3):
        pos = f.tell()
        f.read(4)
        bl = struct.unpack('<I', f.read(4))[0]
        f.seek(pos + bl)

    timestamps = []
    while True:
        pos = f.tell()
        header = f.read(8)
        if len(header) < 8: break
        block_type, block_len = struct.unpack('<II', header)
        if block_type == 6:
            epb = f.read(20)
            iface_id = struct.unpack('<I', epb[:4])[0]
            ts_high, ts_low = struct.unpack('<II', epb[4:12])
            if iface_id == 2:
                timestamps.append((ts_high << 32) | ts_low)
        f.seek(pos + block_len)
    f.close()

    deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    bits = '0' + ''.join('1' if d >= 50000 else '0' for d in deltas)
    flag = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits)-7, 8))
    print(flag.decode('utf-8', errors='replace').rstrip('\x00'))

if __name__ == "__main__":
    solve(sys.argv[1] if len(sys.argv) > 1 else "Breathing_Void.pcap")
```

## Flag

```
EH4X{pc@p5_@re_of+en_mo5+1y_noi5e}
```
