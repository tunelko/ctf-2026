# 247CTF - Multiplication Tables (TLS Private Key Recovery)

## Challenge Info

| Field | Value |
|-------|-------|
| **Name** | Multiplication Tables |
| **Category** | Network Forensics / Cryptography |
| **File** | `bdad12487dbefaac303130233ff2fdb0300c6272.zip` |
| **Description** | Can you recover the private key we used to download the flag over a TLS encrypted connection? |

## Flag

```
247CTF{ca0289c6XXXXXXXXXXXXXXXX5515245e}
```

## Initial Analysis

### File Extraction

```bash
unzip bdad12487dbefaac303130233ff2fdb0300c6272.zip
# Result: multiplication_tables.pcap
```

### PCAP Reconnaissance

```bash
tshark -r multiplication_tables.pcap -q -z io,stat,0
```

The file contains TLS traffic on port 8443. The name "multiplication_tables" is a hint about **RSA factorization** (multiplication of primes).

### Cipher Suite Identification

```bash
tshark -r multiplication_tables.pcap -Y "tls.handshake.type==2" \
  -T fields -e tls.handshake.ciphersuite
```

Result: `0x009d` = **TLS_RSA_WITH_AES_256_GCM_SHA384**

This cipher uses **RSA key exchange**, which means the premaster secret is encrypted with the server's RSA public key. If we recover the private key, we can decrypt all the traffic.

## Certificate Extraction

### Obtain certificate from TLS handshake

```bash
tshark -r multiplication_tables.pcap \
  -Y "tls.handshake.certificate" \
  -T fields -e tls.handshake.certificate 2>/dev/null \
  | head -1 | xxd -r -p > cert.der
```

### Analyze the certificate

```bash
openssl x509 -inform der -in cert.der -text -noout
```

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            4e:e8:bf:aa:74:7e:7b:0f:59:c7:81:66:43:ca:d8:9b:e7:c7:13:7c
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = AU, O = 247CTF, OU = net125, CN = 127.0.0.1
        Subject: C = AU, O = 247CTF, OU = net125, CN = 127.0.0.1
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (1024 bit)   <-- WEAK KEY!
                Modulus:
                    00:d5:ce:b3:39:f0:43:ad:4a:c0:44:e5:68:0b:26:
                    23:63:3d:af:e1:66:d0:2b:55:14:b4:3e:34:b4:d6:
                    ...
                Exponent: 65537 (0x10001)
```

**Critical observation**: The RSA key is only **1024 bits**, which is considered weak and potentially factorable.

### Extract the modulus N

```bash
openssl x509 -inform der -in cert.der -noout -modulus
```

```
Modulus=D5CEB339F043AD4AC044E5680B2623633DAFE166D02B5514B43E34B4D6EE83C8096F016C264846E140D8B00BBE15F5300D44309D29285CB1FE7C223D0119E134C9BB29DACA9B0D1524B89E6C89508D87A39D84C9C72F2493714FB78CA5AC3CD373F14D816844C455A7C1F728200208D6A846E5C57AB4AB7B9CE3AE120E75996B
```

## RSA Modulus Factorization

### Convert N to decimal

```python
n_hex = "D5CEB339F043AD4AC044E5680B2623633DAFE166D02B5514B43E34B4D6EE83C8096F016C264846E140D8B00BBE15F5300D44309D29285CB1FE7C223D0119E134C9BB29DACA9B0D1524B89E6C89508D87A39D84C9C72F2493714FB78CA5AC3CD373F14D816844C455A7C1F728200208D6A846E5C57AB4AB7B9CE3AE120E75996B"
n = int(n_hex, 16)
print(n)
```

```
N = 150140677816147665104219084736753210294673482912091623639530125054379822052662632476220418069658373540642718111649733795871151252404840997598533258881471779382418788567883517594075575444723340506445280678466322096113052425236787558022472785685579744210805862764465110689084328509029822107730392445215781001579
```

### Query FactorDB

FactorDB (http://factordb.com) is a database of known factorizations. We query it using its API:

```bash
curl "http://factordb.com/api?query=150140677816147665104219084736753210294673482912091623639530125054379822052662632476220418069658373540642718111649733795871151252404840997598533258881471779382418788567883517594075575444723340506445280678466322096113052425236787558022472785685579744210805862764465110689084328509029822107730392445215781001579"
```

**Result:**
```json
{
  "id": 1100000001367871143,
  "status": "FF",
  "factors": [
    ["11443069641880629381891581986018548808448150675612774441982091938562801238612124445967724562059877882869924090566492089872161438646198325341704520958011761", 1],
    ["13120664517031861557695339067275706831429518210212092859212127044658713747906482358428924486662467583986570766086011893335839637764790393666582606794678939", 1]
  ]
}
```

- **status: "FF"** = Fully Factored
- Both prime factors p and q were found

### Obtained Factors

```
p = 11443069641880629381891581986018548808448150675612774441982091938562801238612124445967724562059877882869924090566492089872161438646198325341704520958011761

q = 13120664517031861557695339067275706831429518210212092859212127044658713747906482358428924486662467583986570766086011893335839637764790393666582606794678939
```

## Private Key Reconstruction

### RSA Theory

Given:
- **n = p × q** (public modulus)
- **e = 65537** (standard public exponent)
- **φ(n) = (p-1) × (q-1)** (Euler's totient function)
- **d = e⁻¹ mod φ(n)** (private exponent)

With p and q known, we calculate d:

```python
p = 11443069641880629381891581986018548808448150675612774441982091938562801238612124445967724562059877882869924090566492089872161438646198325341704520958011761
q = 13120664517031861557695339067275706831429518210212092859212127044658713747906482358428924486662467583986570766086011893335839637764790393666582606794678939
n = p * q
e = 65537
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)  # Modular inverse in Python 3.8+
```

### Generate PEM file

```python
from Cryptodome.PublicKey import RSA

key = RSA.construct((n, e, d, p, q))
pem = key.export_key()

with open('private_key.pem', 'wb') as f:
    f.write(pem)
```

## TLS Traffic Decryption

### Using ssldump

```bash
ssldump -r multiplication_tables.pcap -k private_key.pem -d
```

### Decrypted Traffic

```
2 11 0.0025 (0.0006)  C>S  application_data
    ---------------------------------------------------------------
    GET /flag.txt HTTP/1.1
    Host: 192.168.10.159:8443
    Connection: keep-alive
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...
    ...
    ---------------------------------------------------------------

2 19 0.0036 (0.0000)  S>C  application_data
    ---------------------------------------------------------------
    247CTF{ca0289c6XXXXXXXXXXXXXXXX5515245e}
    ---------------------------------------------------------------
```

## Scripts

### solve.py - Complete Solver

```python
#!/usr/bin/env python3
"""
TLS Private Key Recovery Solver
For 247CTF "Multiplication Tables" Challenge
"""

import subprocess
import urllib.request
import json
import os
import sys

def extract_certificate(pcap_file):
    """Extract X.509 certificate from TLS handshake"""
    print("[*] Extracting certificate from TLS handshake...")

    result = subprocess.run(
        ['tshark', '-r', pcap_file, '-Y', 'tls.handshake.certificate',
         '-T', 'fields', '-e', 'tls.handshake.certificate'],
        capture_output=True, text=True, stderr=subprocess.DEVNULL
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
        from Crypto.PublicKey import RSA

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
    print("[*] Decrypting TLS traffic...")

    result = subprocess.run(
        ['ssldump', '-r', pcap_file, '-k', key_file, '-d'],
        capture_output=True, text=True, stderr=subprocess.DEVNULL
    )

    # Search for flag in output
    output = result.stdout

    # Look for 247CTF flag pattern
    import re
    match = re.search(r'247CTF\{[a-f0-9]+\}', output)
    if match:
        return match.group(0)

    # Print relevant parts for debugging
    if 'flag.txt' in output.lower():
        print("    Found request to flag.txt")

    return None

def main():
    pcap = sys.argv[1] if len(sys.argv) > 1 else "multiplication_tables.pcap"

    if not os.path.exists(pcap):
        print(f"[-] File not found: {pcap}")
        sys.exit(1)

    print(f"[*] Processing: {pcap}")
    print("=" * 50)

    # Step 1: Extract certificate
    cert_file = extract_certificate(pcap)
    if not cert_file:
        sys.exit(1)

    # Step 2: Get RSA modulus
    n = get_rsa_modulus(cert_file)
    if not n:
        sys.exit(1)

    # Step 3: Factor N
    p, q = factor_with_factordb(n)
    if not p or not q:
        sys.exit(1)

    # Step 4: Generate private key
    key_file = generate_private_key(p, q)

    # Step 5: Decrypt TLS
    flag = decrypt_tls(pcap, key_file)

    print("=" * 50)
    if flag:
        print(f"[+] FLAG: {flag}")
    else:
        print("[-] Flag not found automatically")
        print("[*] Run manually: ssldump -r multiplication_tables.pcap -k private_key.pem -d")

if __name__ == "__main__":
    main()
```

### extract_cert.sh - Extraction Script

```bash
#!/bin/bash
# Extract certificate and RSA parameters from TLS pcap

PCAP="${1:-multiplication_tables.pcap}"

echo "[*] Extracting certificate from $PCAP..."

# Extract certificate as DER
tshark -r "$PCAP" -Y "tls.handshake.certificate" \
    -T fields -e tls.handshake.certificate 2>/dev/null \
    | head -1 | xxd -r -p > cert.der

echo "[*] Certificate info:"
openssl x509 -inform der -in cert.der -text -noout 2>/dev/null | head -20

echo ""
echo "[*] RSA Modulus:"
openssl x509 -inform der -in cert.der -noout -modulus 2>/dev/null

echo ""
echo "[*] To factor N, use FactorDB: http://factordb.com"
```

### decrypt_tls.sh - Decryption Script

```bash
#!/bin/bash
# Decrypt TLS traffic with recovered private key

PCAP="${1:-multiplication_tables.pcap}"
KEY="${2:-private_key.pem}"

if [ ! -f "$KEY" ]; then
    echo "[-] Private key not found: $KEY"
    echo "[*] Run solve.py first to generate the key"
    exit 1
fi

echo "[*] Decrypting TLS traffic..."
echo "[*] PCAP: $PCAP"
echo "[*] Key: $KEY"
echo ""

ssldump -r "$PCAP" -k "$KEY" -d 2>&1 | grep -A5 "application_data"
```

## Tools Used

| Tool | Purpose |
|------|---------|
| tshark | TLS certificate extraction |
| openssl | X.509 certificate parsing |
| FactorDB | RSA modulus factorization |
| Python + pycryptodomex | PEM private key generation |
| ssldump | TLS traffic decryption |

## Key Concepts

### RSA Key Exchange (TLS_RSA_WITH_*)

In cipher suites with RSA key exchange:
1. Client generates a random **premaster secret**
2. Client encrypts the premaster secret with the server's **RSA public key**
3. Server decrypts with its **private key**
4. Both derive session keys from the premaster secret

If we obtain the RSA private key, we can:
- Decrypt the premaster secret
- Derive the session keys
- Decrypt all traffic

### Weakness of 1024-bit RSA

- 1024-bit RSA is considered **insecure** since ~2010
- Can be factored with sufficient resources
- Some weak moduli are already in databases like FactorDB
- The name "multiplication_tables" was the hint: N = p × q

### FactorDB

- Community database of factorizations
- API: `http://factordb.com/api?query=<number>`
- Status codes:
  - `C` = Composite (not factored)
  - `CF` = Composite, factors partially known
  - `FF` = Fully Factored
  - `P` = Prime

## Key Takeaways

1. **File names as hints**: "multiplication_tables" suggests factorization
2. **1024-bit RSA is weak**: Always verify key size
3. **FactorDB is essential**: First tool for RSA factorization in CTFs
4. **Cipher suites matter**: RSA key exchange allows passive decryption with private key

## Mitigations

To avoid this vulnerability:
- Use RSA ≥ 2048 bits (preferably 4096)
- Prefer cipher suites with **Forward Secrecy** (ECDHE, DHE)
- Forward Secrecy prevents retroactive decryption even if the private key is compromised

## References

- [FactorDB](http://factordb.com)
- [RSA Factorization](https://en.wikipedia.org/wiki/RSA_Factoring_Challenge)
- [TLS Cipher Suites](https://wiki.openssl.org/index.php/Manual:Ciphers(1))
- [ssldump](https://github.com/adulau/ssldump)
- [Weak RSA Keys](https://blog.cloudflare.com/why-are-some-keys-small/)
