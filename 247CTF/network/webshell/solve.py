#!/usr/bin/env python3
"""
Complete solver for 247CTF "The Web Shell" Challenge
Extracts and decodes webshell traffic to recover the flag
"""

import subprocess
import base64
import zlib
import re
import os
import sys

# Webshell parameters
KEY = b"81aebe18"
KH = "775d4f83f4e0"
KF = "0120dd0bccc6"

def xor_decrypt(data, key):
    result = bytearray()
    for i in range(len(data)):
        result.append(data[i] ^ key[i % len(key)])
    return bytes(result)

def decode_response(resp):
    start = resp.find(KH)
    end = resp.find(KF)
    if start == -1 or end == -1:
        return None
    start += len(KH)
    b64_data = resp[start:end]
    try:
        decoded = base64.b64decode(b64_data)
        xored = xor_decrypt(decoded, KEY)
        decompressed = zlib.decompress(xored)
        return decompressed.decode('utf-8', errors='replace').strip()
    except:
        return None

def decode_command(hex_data):
    try:
        raw = bytes.fromhex(hex_data).decode('latin-1')
    except:
        return None
    start = raw.find(KH)
    end = raw.find(KF)
    if start == -1 or end == -1:
        return None
    start += len(KH)
    b64_data = raw[start:end]
    b64_clean = ''.join(c for c in b64_data 
        if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    while len(b64_clean) % 4 != 0:
        b64_clean += '='
    try:
        decoded = base64.b64decode(b64_clean)
        xored = xor_decrypt(decoded, KEY)
        decompressed = zlib.decompress(xored)
        return decompressed.decode('utf-8', errors='replace')
    except:
        return None

def main():
    pcap = sys.argv[1] if len(sys.argv) > 1 else "web_shell.pcap"
    
    if not os.path.exists(pcap):
        print(f"Error: {pcap} not found")
        sys.exit(1)
    
    print(f"[*] Processing {pcap}...")
    
    # Extract responses
    print("[*] Extracting responses from TCP streams 160-284...")
    responses = []
    for stream in range(160, 285):
        result = subprocess.run(
            ['tshark', '-r', pcap, '-q', '-z', f'follow,tcp,ascii,{stream}'],
            capture_output=True, text=True, stderr=subprocess.DEVNULL
        )
        match = re.search(r'kkqES1eCIzoxyHXb775d4f83f4e0[A-Za-z0-9+/=]*0120dd0bccc6', result.stdout)
        if match:
            responses.append(match.group(0))
    
    print(f"    Found {len(responses)} responses")
    
    # Extract commands
    print("[*] Extracting POST commands...")
    result = subprocess.run(
        ['tshark', '-r', pcap, '-Y', 
         'http.request.method == POST and http.request.uri contains owned.php',
         '-T', 'fields', '-e', 'http.file_data'],
        capture_output=True, text=True, stderr=subprocess.DEVNULL
    )
    commands = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
    print(f"    Found {len(commands)} commands")
    
    # Map offset to hex value
    print("[*] Reconstructing flag...")
    flag_map = {}
    
    for i, cmd_hex in enumerate(commands):
        cmd = decode_command(cmd_hex)
        if cmd and 'xxd -p -l1 -s' in cmd:
            match = re.search(r'-s(\d+)', cmd)
            if match and i < len(responses):
                offset = int(match.group(1))
                resp = decode_response(responses[i])
                if resp and len(resp) == 2:
                    flag_map[offset] = resp
    
    if not flag_map:
        print("[-] Could not extract flag data")
        sys.exit(1)
    
    max_offset = max(flag_map.keys())
    flag_hex = ''.join(flag_map.get(i, '??') for i in range(max_offset + 1))
    
    try:
        flag = bytes.fromhex(flag_hex).decode()
        print(f"\n[+] FLAG: {flag}")
    except:
        print(f"[-] Partial hex: {flag_hex}")

if __name__ == "__main__":
    main()
