#!/usr/bin/env python3

"""Final solver: try ALL k values for each viable key_len"""
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from sympy.ntheory import discrete_log
import hashlib, sys
from functools import reduce
from multiprocessing import Pool, Value
import ctypes

samples = [
    (227293414901, 1559214942312, 3513364021163),
    (2108076514529, 1231299005176, 2627609083643),
    (1752240335858, 1138499826278, 2917520243087),
    (1564551923739, 283918762399, 2602533803279),
    (1809320390770, 700655135118, 2431482961679),
    (1662077312271, 354214090383, 2820691962743),
    (474213905602, 1149389382916, 3525049671887),
    (2013522313912, 2559608094485, 2679851241659),
]
ct = bytes.fromhex("175a6f682303e313e7cae01f4579702ae6885644d46c15747c39b85e5a1fab667d2be070d383268d23a6387a4b3ec791")

# DLP
print("[*] Computing DLP...")
residues = [1]  # x mod 2 = 1 (all DLPs are odd)
moduli = [2]

for i, (g, h, p) in enumerate(samples):
    q = (p - 1) // 2
    x_full = discrete_log(p, h, g)
    x_mod_q = x_full % q
    residues.append(x_mod_q)
    moduli.append(q)

# CRT
M = reduce(lambda a, b: a * b, moduli)
x = 0
for r, m in zip(residues, moduli):
    Mi = M // m
    yi = pow(Mi, -1, m)
    x = (x + r * Mi * yi) % M

# Verify
for i, (g, h, p) in enumerate(samples):
    assert pow(g, x, p) == h
print(f"[+] x_crt = {x.bit_length()} bits, M = {M.bit_length()} bits")


def try_range(args):
    key_len, k_start, k_end, x_val, M_val, ct_bytes = args
    for k in range(k_start, k_end):
        x_candidate = x_val + k * M_val
        try:
            key = x_candidate.to_bytes(key_len, "big")
        except OverflowError:
            return None
        aes_key = hashlib.sha256(key).digest()
        cipher = AES.new(aes_key, AES.MODE_ECB)
        try:
            pt = unpad(cipher.decrypt(ct_bytes), 16)
            if all(32 <= b < 127 for b in pt):
                return (k, key_len, pt.decode())
        except:
            pass
    return None


# ct = 48 bytes = 3 blocks. Flag between 32 and 47 bytes.
# key_len >= 41 (x_crt doesn't fit in less)
# So key_len in {41, 42, 43, 44, 45, 46, 47}

print("\n[*] Searching for flag...")
for key_len in range(41, 48):
    max_val = (1 << (8 * key_len)) - 1
    if x > max_val:
        print(f"  key_len={key_len}: x > max_val, skip")
        continue

    max_k = (max_val - x) // M
    total = max_k + 1
    print(f"  key_len={key_len}: {total} candidates...", end=" ", flush=True)

    if total > 50_000_000:
        print("too many, parallelizing...")
        # Split into chunks
        chunk_size = 1_000_000
        chunks = []
        for start in range(0, total, chunk_size):
            end = min(start + chunk_size, total)
            chunks.append((key_len, start, end, x, M, ct))

        with Pool(8) as pool:
            for result in pool.imap_unordered(try_range, chunks):
                if result:
                    k, kl, flag = result
                    pool.terminate()
                    print(f"\n[+] k={k}, key_len={kl}")
                    print(f"[+] FLAG: {flag}")
                    sys.exit(0)
        print("  no")
    else:
        result = try_range((key_len, 0, total, x, M, ct))
        if result:
            k, kl, flag = result
            print(f"\n[+] k={k}, key_len={kl}")
            print(f"[+] FLAG: {flag}")
            sys.exit(0)
        else:
            print("no")

print("\n[-] Not found")
