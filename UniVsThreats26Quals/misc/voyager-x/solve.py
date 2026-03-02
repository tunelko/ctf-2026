#!/usr/bin/env python3
"""solve.py — Voyager's Last Command solver
LCG nonce ECDSA attack on secp256k1.
Nonces: k_{i+1} = a*k_i + b (mod n). Known a, unknown b.
3 signatures => recover d.
"""
import socket, time, re, sys
from hashlib import sha256
from Crypto.Cipher import AES
from ecdsa import SECP256k1
from ecdsa.numbertheory import inverse_mod

HOST = '194.102.62.175'
PORT = 22011
n = SECP256k1.order
G = SECP256k1.generator

def modinv(x, m=n):
    return pow(x, m - 2, m)

# Connect and get data
s = socket.socket()
s.connect((HOST, PORT))
time.sleep(2)
banner = s.recv(8192).decode()
print(banner[:200])

# Parse banner
a_m = re.search(r'LCG\s+a\s*:\s*(0x[0-9a-fA-F]+)', banner)
qx_m = re.search(r'Qx\s*:\s*(0x[0-9a-fA-F]+)', banner)
qy_m = re.search(r'Qy\s*:\s*(0x[0-9a-fA-F]+)', banner)
data_lines = re.findall(r'Data\s*:.*?│|([0-9a-f]{20,})', banner)
# Get ciphertext
ct_parts = re.findall(r'[0-9a-f]{40,}', banner.split('Data')[1]) if 'Data' in banner else []
ct_hex = ''.join(ct_parts)

a = int(a_m.group(1), 16)
Qx = int(qx_m.group(1), 16)
Qy = int(qy_m.group(1), 16)

print(f"a  = {hex(a)}")
print(f"Qx = {hex(Qx)}")
print(f"ct = {ct_hex}")

# Get 3 signatures
sigs = []
for i in range(3):
    msg = format(i + 1, '02x')
    s.sendall(f'SIGN {msg}\n'.encode())
    time.sleep(1)
    resp = s.recv(4096).decode()
    r_m = re.search(r'r\s*:\s*(0x[0-9a-fA-F]+)', resp)
    s_m = re.search(r's\s*:\s*(0x[0-9a-fA-F]+)', resp)
    z_m = re.search(r'z\s*:\s*(0x[0-9a-fA-F]+)', resp)
    sig = (int(r_m.group(1), 16), int(s_m.group(1), 16), int(z_m.group(1), 16))
    sigs.append(sig)
    print(f"Sig {i+1}: r={hex(sig[0])[:20]}... s={hex(sig[1])[:20]}... z={hex(sig[2])[:20]}...")
s.close()

r1, s1, z1 = sigs[0]
r2, s2, z2 = sigs[1]
r3, s3, z3 = sigs[2]

# ECDSA: s_i = k_i^{-1} * (z_i + r_i * d) mod n
# => k_i = modinv(s_i) * (z_i + r_i * d) mod n
# => k_i = e_i + c_i * d  where e_i = modinv(s_i)*z_i, c_i = modinv(s_i)*r_i

# LCG: k2 = a*k1 + b, k3 = a*k2 + b
# => k3 - a*k2 = k2 - a*k1  (both equal b)
# => k3 - a*k2 - k2 + a*k1 = 0
# => k3 - (a+1)*k2 + a*k1 = 0

c1 = modinv(s1) * r1 % n
e1 = modinv(s1) * z1 % n
c2 = modinv(s2) * r2 % n
e2 = modinv(s2) * z2 % n
c3 = modinv(s3) * r3 % n
e3 = modinv(s3) * z3 % n

# k3 - (a+1)*k2 + a*k1 = 0
# (e3 + c3*d) - (a+1)*(e2 + c2*d) + a*(e1 + c1*d) = 0
# d * (c3 - (a+1)*c2 + a*c1) + (e3 - (a+1)*e2 + a*e1) = 0

A_coeff = (c3 - (a + 1) * c2 + a * c1) % n
B_coeff = (e3 - (a + 1) * e2 + a * e1) % n

d = (-B_coeff * modinv(A_coeff)) % n
print(f"\nPrivate key d = {hex(d)}")

# Verify: compute k1 and check against r1
k1 = (e1 + c1 * d) % n
P = k1 * G
print(f"k1*G.x = {hex(P.x())}")
print(f"r1     = {hex(r1)}")
print(f"Nonce verification: {P.x() % n == r1}")

if P.x() % n != r1:
    # Try with negated s values (low-s normalization)
    print("\nTrying with s values negated...")
    for neg_mask in range(1, 8):
        ss = [s1, s2, s3]
        for bit in range(3):
            if neg_mask & (1 << bit):
                ss[bit] = n - ss[bit]

        c1_ = modinv(ss[0]) * r1 % n
        e1_ = modinv(ss[0]) * z1 % n
        c2_ = modinv(ss[1]) * r2 % n
        e2_ = modinv(ss[1]) * z2 % n
        c3_ = modinv(ss[2]) * r3 % n
        e3_ = modinv(ss[2]) * z3 % n

        A_ = (c3_ - (a + 1) * c2_ + a * c1_) % n
        B_ = (e3_ - (a + 1) * e2_ + a * e1_) % n

        if A_ == 0:
            continue
        d_ = (-B_ * modinv(A_)) % n
        k1_ = (e1_ + c1_ * d_) % n
        P_ = k1_ * G
        if P_.x() % n == r1:
            d = d_
            print(f"  Found with mask {neg_mask}: d = {hex(d)}")
            break

# Decrypt
key_bytes = sha256(d.to_bytes(32, 'big')).digest()[:16]
cipher = AES.new(key_bytes, AES.MODE_ECB)
pt = cipher.decrypt(bytes.fromhex(ct_hex))
print(f"\nDecrypted: {pt}")

flag_m = re.search(rb'EHAX\{[^}]+\}', pt)
if flag_m:
    flag = flag_m.group().decode()
    print(f"\nFlag: {flag}")
    with open("flag.txt", "w") as f:
        f.write(flag)
else:
    # Maybe flag has different format or padding
    try:
        text = pt.rstrip(b'\x00').rstrip(b'\x10\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08\x07\x06\x05\x04\x03\x02\x01')
        print(f"Text: {text}")
    except:
        pass
    # Try all possible d candidates
    print("No flag found in decryption")
