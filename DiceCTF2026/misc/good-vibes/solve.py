#!/usr/bin/env python3
"""
Challenge: good vibes
Category:  misc (network/crypto)
Platform:  diceCTF 2026

Decrypts traffic from a custom VPN ("vibepn") whose session key
is derived from time(NULL) via a weak LCG PRNG.
"""
import subprocess
import struct
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import os
PCAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "challenge.pcap")

# === LCG key derivation (from vpn_derive_session_key) ===
# seed = time(NULL)
# for i in 0..31: seed = seed * 0x19660d + 0x3c6ef35f; key[i] = seed & 0xff
def derive_key(seed):
    key = bytearray(32)
    val = seed & 0xFFFFFFFF
    for i in range(32):
        val = (val * 0x19660d + 0x3c6ef35f) & 0xFFFFFFFF
        key[i] = val & 0xFF
    return bytes(key)

# === Extract UDP packets on VPN port 5959 ===
def extract_vpn_packets(pcap):
    result = subprocess.run([
        'tshark', '-r', pcap,
        '-Y', 'udp.port == 5959',
        '-T', 'fields', '-e', 'ip.src', '-e', 'data.data', '-e', 'frame.time_epoch'
    ], capture_output=True, text=True)

    packets = []
    for line in result.stdout.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.strip().split('\t')
        packets.append({
            'src': parts[0],
            'raw': bytes.fromhex(parts[1]),
            'ts': float(parts[2])
        })
    return packets

# === Parse VPN packet header ===
# Format: BE TYPE LEN[2] SEQ[4] NONCE[12] CIPHERTEXT[...] TAG[16]
# Types: 0x01=HELLO, 0x02=HELLO_RESP, 0x03=CHALLENGE, 0x04=ACK, 0x10=DATA, 0x20=KEEPALIVE
def parse_vpn_packet(raw):
    return {
        'magic': raw[0],        # 0xBE
        'type': raw[1],
        'length': struct.unpack('>H', raw[2:4])[0],
        'seq': struct.unpack('>I', raw[4:8])[0],
        'nonce': raw[8:20],     # 12 bytes
        'ct_tag': raw[20:],     # ciphertext + 16-byte GCM tag
        'header': raw[:20],     # AAD for GCM
    }

def main():
    print("[*] Extracting VPN packets from PCAP...")
    packets = extract_vpn_packets(PCAP)
    print(f"    Total VPN packets: {len(packets)}")

    # Get base timestamp from first data packet
    first_data = None
    for pkt in packets:
        if pkt['raw'][1] in (0x10, 0x20):
            first_data = pkt
            break
    base_time = int(first_data['ts'])
    print(f"    First data packet epoch: {base_time}")

    # === Step 1: Brute-force LCG seed ===
    print("[*] Brute-forcing LCG seed (time-based, +/- 2 hours)...")
    vpn = parse_vpn_packet(first_data['raw'])
    found_seed = None

    for delta in range(-7200, 7200):
        seed = base_time + delta
        key = derive_key(seed)
        try:
            aesgcm = AESGCM(key)
            aesgcm.decrypt(vpn['nonce'], vpn['ct_tag'], vpn['header'])
            found_seed = seed
            break
        except Exception:
            pass

    if not found_seed:
        print("[-] Failed to find seed")
        sys.exit(1)

    print(f"[+] Found seed: {found_seed} (delta={found_seed - base_time}s from PCAP time)")
    key = derive_key(found_seed)
    print(f"    Session key: {key.hex()}")
    aesgcm = AESGCM(key)

    # === Step 2: Decrypt all data packets ===
    print("[*] Decrypting VPN traffic...")
    decrypted = 0
    flag = None

    for pkt in packets:
        ptype = pkt['raw'][1]
        if ptype not in (0x10, 0x20):
            continue
        vpn = parse_vpn_packet(pkt['raw'])
        try:
            pt = aesgcm.decrypt(vpn['nonce'], vpn['ct_tag'], vpn['header'])
            decrypted += 1
        except Exception:
            continue

        # Check for flag: non-link-local IPv6 with ASCII src/dst addresses
        if len(pt) >= 40 and (pt[0] >> 4) == 6:
            src_addr = pt[8:24]
            if src_addr[:2] not in (b'\xfe\x80', b'\xff\x02'):
                # The entire "IPv6 packet" is the flag as raw ASCII
                flag = pt.decode('ascii', errors='replace')

    print(f"    Decrypted {decrypted} packets")

    if flag:
        print(f"\n[+] Flag: {flag}")
    else:
        print("[-] Flag not found in decrypted traffic")

if __name__ == "__main__":
    main()
