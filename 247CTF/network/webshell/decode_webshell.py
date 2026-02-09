#!/usr/bin/env python3
"""
Webshell Traffic Decoder for 247CTF "The Web Shell" Challenge
Decodes XOR+gzip encrypted PHP webshell communications
"""

import base64
import zlib
import re
import sys

# Webshell encryption parameters (extracted from owned.php)
KEY = b"81aebe18"
KH = "775d4f83f4e0"  # Start delimiter
KF = "0120dd0bccc6"  # End delimiter

def xor_decrypt(data, key):
    """XOR decrypt data with repeating key"""
    result = bytearray()
    for i in range(len(data)):
        result.append(data[i] ^ key[i % len(key)])
    return bytes(result)

def decode_response(resp):
    """Decode webshell response: base64 -> XOR -> gzip decompress"""
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
    """Decode webshell command from hex POST data"""
    raw = bytes.fromhex(hex_data).decode('latin-1')
    start = raw.find(KH)
    end = raw.find(KF)
    if start == -1 or end == -1:
        return None
    start += len(KH)
    b64_data = raw[start:end]
    # Clean non-base64 characters
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

def reconstruct_flag(commands_file, responses_file):
    """Reconstruct flag from xxd commands and responses"""
    with open(commands_file, 'r') as f:
        commands = [line.strip() for line in f if line.strip()]
    
    with open(responses_file, 'r') as f:
        responses = [line.strip() for line in f if line.strip()]
    
    # Map offset -> hex value
    flag_map = {}
    for i, cmd_hex in enumerate(commands):
        cmd = decode_command(cmd_hex)
        if cmd and 'xxd -p -l1 -s' in cmd:
            match = re.search(r'-s(\d+)', cmd)
            if match:
                offset = int(match.group(1))
                resp = decode_response(responses[i])
                if resp and len(resp) == 2:
                    flag_map[offset] = resp
    
    # Reconstruct in order
    if not flag_map:
        return None
    max_offset = max(flag_map.keys())
    flag_hex = ''.join(flag_map.get(i, '??') for i in range(max_offset + 1))
    return bytes.fromhex(flag_hex).decode()

if __name__ == "__main__":
    print("Webshell Decoder")
    print("================")
    print(f"XOR Key: {KEY.decode()}")
    print(f"Start delimiter: {KH}")
    print(f"End delimiter: {KF}")
    print("\nUsage:")
    print("  1. Extract responses: tshark ... > responses.txt")
    print("  2. Extract commands: tshark ... > commands.txt")
    print("  3. Run: python3 decode_webshell.py commands.txt responses.txt")
    
    if len(sys.argv) == 3:
        flag = reconstruct_flag(sys.argv[1], sys.argv[2])
        if flag:
            print(f"\nFlag: {flag}")
