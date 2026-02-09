#!/usr/bin/env python3
"""
TLS Private Key Recovery Solver
For 247CTF "Multiplication Tables" Challenge

Recovers RSA private key by factoring weak 1024-bit modulus,
then decrypts TLS traffic to extract the flag.
"""

import subprocess
import urllib.request
import json
import os
import sys
import re

def extract_certificate(pcap_file):
    """Extract X.509 certificate from TLS handshake"""
    print("[*] Extracting certificate from TLS handshake...")

    result = subprocess.run(
        ['tshark', '-r', pcap_file, '-Y', 'tls.handshake.certificate',
         '-T', 'fields', '-e', 'tls.handshake.certificate'],
        capture_output=True, text=True
    )

    cert_hex = result.stdout.strip().split('\n')[0]
    if not cert_hex:
        print("[-] No certificate found")
        return None

    # Save as DER
    cert_der = bytes.fromhex(cert_hex.replace(':', ''))
    with open('cert.der', 'wb') as f:
        f.write(cert_der)

    print(f"    Certificate saved ({len(cert_der)} bytes)")
    return 'cert.der'

def get_rsa_modulus(cert_file):
    """Extract RSA modulus from certificate"""
    print("[*] Extracting RSA modulus...")

    result = subprocess.run(
        ['openssl', 'x509', '-inform', 'der', '-in', cert_file, '-noout', '-modulus'],
        capture_output=True, text=True
    )

    # Parse "Modulus=HEXVALUE"
    line = result.stdout.strip()
    if not line.startswith('Modulus='):
        print("[-] Could not extract modulus")
        return None

    n_hex = line.split('=')[1]
    n = int(n_hex, 16)
    print(f"    N = {str(n)[:50]}... ({n.bit_length()} bits)")
    return n

def factor_with_factordb(n):
    """Query FactorDB API to factor N"""
    print("[*] Querying FactorDB for factorization...")

    url = f"http://factordb.com/api?query={n}"
    try:
        response = urllib.request.urlopen(url, timeout=30)
        data = json.loads(response.read().decode())

        if data['status'] != 'FF':
            print(f"[-] Number not fully factored (status: {data['status']})")
            print("[*] Try submitting to FactorDB or use yafu/msieve locally")
            return None, None

        factors = data['factors']
        if len(factors) != 2:
            print(f"[-] Expected 2 factors, got {len(factors)}")
            return None, None

        p = int(factors[0][0])
        q = int(factors[1][0])

        # Verify
        if p * q != n:
            print("[-] Factor verification failed")
            return None, None

        print(f"    p = {str(p)[:40]}...")
        print(f"    q = {str(q)[:40]}...")
        print("    [+] Factors verified: p * q == N")
        return p, q

    except Exception as e:
        print(f"[-] FactorDB error: {e}")
        return None, None

def generate_private_key(p, q, e=65537):
    """Generate RSA private key from factors"""
    print("[*] Generating private key...")

    try:
        from Cryptodome.PublicKey import RSA
    except ImportError:
        try:
            from Crypto.PublicKey import RSA
        except ImportError:
            print("[-] pycryptodome not installed")
            print("[*] Install with: pip install pycryptodomex")
            return None

    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    key = RSA.construct((n, e, d, p, q))
    pem = key.export_key()

    with open('private_key.pem', 'wb') as f:
        f.write(pem)

    print("    Private key saved to private_key.pem")
    return 'private_key.pem'

def decrypt_tls(pcap_file, key_file):
    """Decrypt TLS traffic and extract flag"""
    print("[*] Decrypting TLS traffic with ssldump...")

    result = subprocess.run(
        ['ssldump', '-r', pcap_file, '-k', key_file, '-d'],
        capture_output=True, text=True
    )

    output = result.stdout

    # Look for 247CTF flag pattern
    match = re.search(r'247CTF\{[a-f0-9]+\}', output)
    if match:
        return match.group(0)

    # Check if we found HTTP traffic
    if 'GET /flag.txt' in output:
        print("    Found request to /flag.txt")
        # Try to find the response content
        lines = output.split('\n')
        for i, line in enumerate(lines):
            if '247CTF' in line:
                return line.strip()

    return None

def main():
    pcap = sys.argv[1] if len(sys.argv) > 1 else "multiplication_tables.pcap"

    if not os.path.exists(pcap):
        print(f"[-] File not found: {pcap}")
        sys.exit(1)

    print(f"[*] TLS Private Key Recovery Solver")
    print(f"[*] Target: {pcap}")
    print("=" * 60)

    # Step 1: Extract certificate
    cert_file = extract_certificate(pcap)
    if not cert_file:
        sys.exit(1)

    # Step 2: Get RSA modulus
    n = get_rsa_modulus(cert_file)
    if not n:
        sys.exit(1)

    # Step 3: Factor N using FactorDB
    p, q = factor_with_factordb(n)
    if not p or not q:
        print("\n[-] Could not factor N automatically")
        print("[*] Manual options:")
        print(f"    1. Check FactorDB: http://factordb.com/?query={n}")
        print("    2. Use yafu: yafu 'factor(N)'")
        print("    3. Use msieve: msieve -q N")
        sys.exit(1)

    # Step 4: Generate private key
    key_file = generate_private_key(p, q)
    if not key_file:
        sys.exit(1)

    # Step 5: Decrypt TLS traffic
    flag = decrypt_tls(pcap, key_file)

    print("=" * 60)
    if flag:
        print(f"\n[+] FLAG: {flag}\n")
    else:
        print("\n[-] Flag not found automatically")
        print("[*] Run manually to inspect traffic:")
        print(f"    ssldump -r {pcap} -k {key_file} -d | less")

if __name__ == "__main__":
    main()
