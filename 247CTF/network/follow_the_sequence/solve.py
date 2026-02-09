#!/usr/bin/env python3
"""
MPTCP Subflow Reconstruction Solver
For 247CTF "Follow The Sequence" Challenge
"""

import subprocess
import os
import sys

def extract_mptcp_data(pcap_files):
    """Extract DSN and payload from MPTCP pcap files"""
    all_data = {}
    
    for pcap in pcap_files:
        print(f"[*] Processing {pcap}...")
        result = subprocess.run(
            ['tshark', '-r', pcap, '-T', 'fields',
             '-e', 'tcp.options.mptcp.rawdataseqno',
             '-e', 'tcp.options.mptcp.datalvllen',
             '-e', 'tcp.payload'],
            capture_output=True, text=True, stderr=subprocess.DEVNULL
        )
        
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) >= 3 and parts[0] and parts[2]:
                try:
                    dsn = int(parts[0])
                    payload = parts[2].replace(':', '')
                    # Keep longest payload for each DSN
                    if dsn not in all_data or len(payload) > len(all_data[dsn]):
                        all_data[dsn] = payload
                except:
                    pass
    
    return all_data

def reconstruct_data(data_chunks):
    """Reconstruct data by ordering by DSN"""
    sorted_dsns = sorted(data_chunks.keys())
    print(f"[*] Total chunks: {len(sorted_dsns)}")
    print(f"[*] DSN range: {sorted_dsns[0]} - {sorted_dsns[-1]}")
    
    combined = b''
    for dsn in sorted_dsns:
        try:
            combined += bytes.fromhex(data_chunks[dsn])
        except:
            pass
    
    return combined

def main():
    # Find pcap files
    pcap_files = []
    for f in ['chall-i1.pcap', 'chall-i2.pcap', 'chall-i3.pcap']:
        if os.path.exists(f):
            pcap_files.append(f)
    
    if not pcap_files:
        print("[-] No pcap files found. Unzip the challenge first.")
        sys.exit(1)
    
    print(f"[*] Found {len(pcap_files)} pcap files")
    
    # Extract and combine
    data = extract_mptcp_data(pcap_files)
    combined = reconstruct_data(data)
    
    print(f"[*] Combined size: {len(combined)} bytes")
    
    # Save combined data
    with open('combined.bin', 'wb') as f:
        f.write(combined)
    print("[*] Saved to combined.bin")
    
    # Check for HTTP response
    if combined[:4] == b'HTTP':
        print("[*] Found HTTP response")
        # Find ZIP signature
        pk_offset = combined.find(b'PK')
        if pk_offset > 0:
            print(f"[*] ZIP starts at offset {pk_offset}")
            with open('extracted.zip', 'wb') as f:
                f.write(combined[pk_offset:])
            print("[*] Extracted ZIP saved to extracted.zip")
            print("[*] Unzip and check flag/*.jpg images")
            
            # Try to unzip
            subprocess.run(['unzip', '-o', 'extracted.zip'], 
                          stderr=subprocess.DEVNULL)
            print("\n[+] Check Here.jpg for the flag!")

if __name__ == "__main__":
    main()
