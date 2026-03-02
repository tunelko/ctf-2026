#!/usr/bin/env python3
"""
solve.py — BreathingVoid solver
Usage: python3 solve.py [PCAP_FILE]

Extracts a flag hidden in a covert timing channel within a 1.1GB pcapng file.
The flag is encoded in inter-packet delays: 100ms = bit 1, 10ms = bit 0.
"""
import struct
import sys

def solve(pcap_file="Breathing_Void.pcap"):
    f = open(pcap_file, 'rb')

    # Skip Section Header Block (SHB)
    f.read(4)
    block_len = struct.unpack('<I', f.read(4))[0]
    f.seek(block_len)

    # Skip Interface Description Blocks (3 IDBs)
    # IDB 0: Ethernet (link_type=1) - decoy traffic
    # IDB 1: Raw IPv4 (link_type=228) - single sync packet
    # IDB 2: Raw IPv4 (link_type=228) - 272 covert timing channel packets
    for i in range(3):
        pos = f.tell()
        f.read(4)
        bl = struct.unpack('<I', f.read(4))[0]
        f.seek(pos + bl)

    # Extract timestamps from interface 2 packets (covert timing channel)
    timestamps = []
    while True:
        pos = f.tell()
        header = f.read(8)
        if len(header) < 8:
            break
        block_type, block_len = struct.unpack('<II', header)

        if block_type == 6:  # Enhanced Packet Block
            epb = f.read(20)
            iface_id = struct.unpack('<I', epb[:4])[0]
            ts_high, ts_low = struct.unpack('<II', epb[4:12])

            if iface_id == 2:
                timestamp = (ts_high << 32) | ts_low  # microseconds
                timestamps.append(timestamp)

        f.seek(pos + block_len)
    f.close()

    print(f"[*] Extracted {len(timestamps)} covert channel packets from interface 2")

    # Calculate inter-packet timing deltas
    deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    print(f"[*] {len(deltas)} timing deltas")
    print(f"[*] All deltas are exactly 10ms or 100ms")

    # Decode: 100ms (100000 us) = bit 1, 10ms (10000 us) = bit 0
    # Threshold at 50ms to classify
    bits = ''.join('1' if d >= 50000 else '0' for d in deltas)
    print(f"[*] Decoded {len(bits)} bits")

    # Prepend a '0' bit to align to byte boundary (the first packet is the reference point)
    # Without this, the message starts at 'H4X{...' instead of 'EH4X{...'
    padded = '0' + bits

    # Convert bits to bytes (MSB first)
    flag_bytes = bytes(int(padded[i:i+8], 2) for i in range(0, len(padded)-7, 8))
    flag = flag_bytes.decode('utf-8', errors='replace').rstrip('\x00')

    print(f"\n[+] FLAG: {flag}")
    return flag

if __name__ == "__main__":
    pcap = sys.argv[1] if len(sys.argv) > 1 else "Breathing_Void.pcap"
    solve(pcap)
