#!/usr/bin/env python3
from pwn import *
import re, sys

sys.path.insert(0, ".")
from tokencrypt import _c_encrypt, _c_decrypt, _build_m_rows_from_seed, _mat_mul_rows, _mat_inv_rows, MASK24, TokenCrypt

io = remote("tokencrypt-3aad1fd8.challenges.bsidessf.net", 1616)
io.recvuntil(b"tc.ai> ")

# Get flag
io.sendline(b"getflag")
io.recvuntil(b"tc.ai(")
flag_data = io.recvuntil(b")").decode()
parts = flag_data.rstrip(")").split(",", 1)
flag_rounds = int(parts[0])
flag_cts = [int(x.strip()) for x in parts[1].strip().strip("[]").split(",")]
log.info(f"Flag: {flag_rounds} rounds, {len(flag_cts)} tokens: {flag_cts}")
io.recvuntil(b"tc.ai> ")

# Set to Fastest (16 rounds)
io.sendline(b"setsecurity")
io.recvuntil(b"[Default]: ")
io.sendline(b"Fastest")
io.recvuntil(b"tc.ai> ")

# Query known plaintexts at 16 rounds
tokens = list(range(100000, 100025))
io.sendline(b"encrypt")
io.recvuntil(b"tokens> ")
io.sendline(str(tokens).encode())
line = io.recvline().decode()
m = re.search(r"\[([^\]]+)\]", line)
cts16 = [int(x.strip()) for x in m.group(1).split(",")]
log.info(f"16-round CTs: {cts16[:5]}...")
io.recvuntil(b"tc.ai> ")
io.close()

# Brute force s (16-bit key for Feistel)
log.info("Brute-forcing s...")
for s in range(65536):
    f0 = _c_encrypt(tokens[0], s, 16)
    f1 = _c_encrypt(tokens[1], s, 16)
    f2 = _c_encrypt(tokens[2], s, 16)

    # Check: are all (f_i, ct_i) pairs consistent with a single affine M+b?
    # Build M from 24 independent equations, verify on remaining pair

    f_all = [_c_encrypt(t, s, 16) for t in tokens]

    # Use Gaussian elimination to solve for M
    # For each output bit j: solve M_row[j] such that M_row[j] · f_diff[i] = ct_diff[i][j]

    f_diffs = [f_all[i] ^ f_all[0] for i in range(1, 25)]
    ct_diffs = [cts16[i] ^ cts16[0] for i in range(1, 25)]

    # Solve one row of M as sanity check
    # M_row[0] · f_diff[i] = bit 0 of ct_diff[i], for all i
    # This is a system of 24 equations in 24 unknowns over GF(2)

    aug = []
    for i in range(24):
        row = f_diffs[i]  # 24-bit vector
        target = (ct_diffs[i] >> 0) & 1  # bit 0 of ct_diff
        aug.append((row, target))

    # Gaussian elimination
    mat = [list(range(24)) for _ in range(24)]  # placeholder

    # For efficiency: just check a FEW specific triples
    ok = True

    # Solve M: for each output bit j (0-23):
    # Find 24-bit vector M_j such that M_j · f_diffs[i] = bit j of ct_diffs[i]

    M_rows = []
    valid = True
    for j in range(24):
        # Augmented matrix: 24 equations, 24 unknowns + 1 target
        A = []
        for i in range(24):
            row = [(f_diffs[i] >> k) & 1 for k in range(24)]
            target = (ct_diffs[i] >> j) & 1
            A.append(row + [target])

        # Gaussian elimination over GF(2)
        for col in range(24):
            pivot = None
            for r in range(col, 24):
                if A[r][col] == 1:
                    pivot = r
                    break
            if pivot is None:
                valid = False
                break
            A[col], A[pivot] = A[pivot], A[col]
            for r in range(24):
                if r != col and A[r][col] == 1:
                    A[r] = [(A[r][k] ^ A[col][k]) for k in range(25)]

        if not valid:
            break

        # Extract solution
        sol = 0
        for k in range(24):
            sol |= A[k][24] << k
        M_rows.append(sol)

    if not valid:
        continue

    # Compute b and verify encrypt(tokens[0])
    b = 0
    for j in range(24):
        bit = M_rows[j] & f_all[0]
        parity = bin(bit).count("1") & 1
        b |= ((cts16[0] >> j) & 1) ^ parity << j

    # Verify on ALL 25 points
    all_match = True
    for i in range(25):
        expected = 0
        for j in range(24):
            bit = M_rows[j] & f_all[i]
            parity = bin(bit).count("1") & 1
            expected |= (parity ^ ((b >> j) & 1)) << j
        if expected != cts16[i]:
            all_match = False
            break

    if all_match:
        log.success(f"Found s = {s}")
        # decrypt_chunk(y) = feistel_decrypt(M_inv * (y XOR b), s)

        M_inv = _mat_inv_rows(M_rows)

        # Decrypt flag
        flag_chunks = flag_rounds // 16
        plaintext_tokens = []
        for ct in flag_cts:
            y = ct
            for c in reversed(range(flag_chunks)):
                # Inverse affine
                z = _mat_mul_rows(M_inv, (y ^ b) & MASK24) & MASK24
                # Inverse Feistel
                y = _c_decrypt(z, s, 16) ^ c
            plaintext_tokens.append(y)

        log.success(f"Plaintext tokens: {plaintext_tokens}")
        flag = "".join(chr(t) for t in plaintext_tokens if 0 < t < 128)
        log.success(f"FLAG: {flag}")
        break

    if s % 5000 == 0:
        log.info(f"  s={s}...")
