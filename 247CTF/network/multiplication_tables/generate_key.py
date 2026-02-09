#!/usr/bin/env python3
"""
Generate RSA private key from known prime factors
For 247CTF "Multiplication Tables" Challenge

The RSA modulus N from the TLS certificate was factored using FactorDB.
"""

# Known prime factors from FactorDB
p = 11443069641880629381891581986018548808448150675612774441982091938562801238612124445967724562059877882869924090566492089872161438646198325341704520958011761

q = 13120664517031861557695339067275706831429518210212092859212127044658713747906482358428924486662467583986570766086011893335839637764790393666582606794678939

# Public exponent (standard)
e = 65537

# Calculate RSA parameters
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

print("[*] RSA Parameters")
print("=" * 60)
print(f"p = {p}")
print(f"q = {q}")
print(f"n = {n}")
print(f"e = {e}")
print(f"d = {d}")
print(f"phi = {phi}")
print("=" * 60)

# Verify: n should match the certificate
n_from_cert = 0xD5CEB339F043AD4AC044E5680B2623633DAFE166D02B5514B43E34B4D6EE83C8096F016C264846E140D8B00BBE15F5300D44309D29285CB1FE7C223D0119E134C9BB29DACA9B0D1524B89E6C89508D87A39D84C9C72F2493714FB78CA5AC3CD373F14D816844C455A7C1F728200208D6A846E5C57AB4AB7B9CE3AE120E75996B

print(f"\n[*] Verification: n == n_from_cert: {n == n_from_cert}")

# Generate PEM file
try:
    from Cryptodome.PublicKey import RSA
except ImportError:
    from Crypto.PublicKey import RSA

key = RSA.construct((n, e, d, p, q))

# Save private key
with open('private_key.pem', 'wb') as f:
    f.write(key.export_key())
print("\n[+] Private key saved to: private_key.pem")

# Save public key
with open('public_key.pem', 'wb') as f:
    f.write(key.publickey().export_key())
print("[+] Public key saved to: public_key.pem")

# Display key
print("\n[*] Private Key (PEM format):")
print(key.export_key().decode())
