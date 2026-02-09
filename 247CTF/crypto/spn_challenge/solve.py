#!/usr/bin/env python3
"""
Solve SPN cipher by brute forcing the weak key space.
Key is only [a, b] * 4 = 65536 possibilities.
"""

rounds = 5
block_size = 8

sa = {0: 15, 1: 2, 2: 14, 3: 0, 4: 1, 5: 3, 6: 10, 7: 6, 8: 4, 9: 11, 10: 9, 11: 7, 12: 13, 13: 12, 14: 8, 15: 5}
sb = {0: 12, 1: 8, 2: 13, 3: 6, 4: 9, 5: 1, 6: 11, 7: 14, 8: 5, 9: 10, 10: 3, 11: 4, 12: 0, 13: 15, 14: 7, 15: 2}

# Inverse S-boxes for decryption
sa_inv = {v: k for k, v in sa.items()}
sb_inv = {v: k for k, v in sb.items()}

to_bin = lambda x, n=block_size: format(x, "b").zfill(n)
to_int = lambda x: int(x, 2)
to_chr = lambda x: "".join([chr(i) for i in x])
to_ord = lambda x: [ord(i) for i in x]
bin_join = lambda x, n=int(block_size / 2): (str(x[0]).zfill(n) + str(x[1]).zfill(n))
bin_split = lambda x: (x[0 : int(block_size / 2)], x[int(block_size / 2) :])
str_split = lambda x: [x[i : i + block_size] for i in range(0, len(x), block_size)]
xor = lambda x, y: x ^ y

def s(a, b):
    return sa[a], sb[b]

def s_inv(a, b):
    return sa_inv[a], sb_inv[b]

def p(a):
    return a[5] + a[2] + a[3] + a[1] + a[6] + a[0] + a[7] + a[4]

def p_inv(a):
    result = [''] * 8
    result[5] = a[0]
    result[2] = a[1]
    result[3] = a[2]
    result[1] = a[3]
    result[6] = a[4]
    result[0] = a[5]
    result[7] = a[6]
    result[4] = a[7]
    return ''.join(result)

def ks(k):
    """Key schedule - k is a list of ints"""
    result = []
    for i in range(rounds):
        rk = k[i:] + k[:i]
        result.append(rk[:block_size])
    return result

def kx(state, k):
    """XOR state with key - both are lists of ints"""
    return [state[i] ^ k[i] for i in range(len(state))]

def en(e):
    """Encrypt one round (S-box + P-box) for each byte - e is list of ints"""
    encrypted = []
    for val in e:
        a, b = bin_split(to_bin(val))
        sa_out, sb_out = s(to_int(a), to_int(b))
        pe = p(bin_join((to_bin(sa_out, int(block_size / 2)), to_bin(sb_out, int(block_size / 2)))))
        encrypted.append(to_int(pe))
    return encrypted

def de(e):
    """Decrypt one round (inverse P-box + inverse S-box) for each byte"""
    decrypted = []
    for val in e:
        pe_inv = p_inv(to_bin(val))
        a, b = bin_split(pe_inv)
        sa_out, sb_out = s_inv(to_int(a), to_int(b))
        decrypted.append((sa_out << 4) | sb_out)
    return decrypted

def r_encrypt(plaintext_bytes, key):
    """Encrypt plaintext with key - both are lists of ints"""
    keys = ks(key)
    # Pad to multiple of block_size
    while len(plaintext_bytes) % block_size != 0:
        plaintext_bytes = plaintext_bytes + [0]

    # Split into blocks
    blocks = [plaintext_bytes[i:i+block_size] for i in range(0, len(plaintext_bytes), block_size)]

    result = []
    for block in blocks:
        state = list(block)
        for i in range(rounds):
            state = kx(state, keys[i])
            state = en(state)
        result.extend(state)
    return result

def r_decrypt(ciphertext, key):
    """Decrypt ciphertext with key - both are lists of ints"""
    keys = ks(key)

    # Split into blocks
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]

    result = []
    for block in blocks:
        state = list(block)
        for i in range(rounds - 1, -1, -1):
            state = de(state)
            state = kx(state, keys[i])
        result.extend(state)
    return result

# Encrypted flag
encrypted = [190, 245, 36, 15, 132, 103, 116, 14, 59, 38, 28, 203, 158, 245, 222, 157, 36, 100, 240, 206, 36, 205, 51, 206, 90, 212, 222, 245, 83, 14, 222, 206, 163, 38, 59, 157, 83, 203, 28, 27]

# Known plaintext prefix
known = [ord(c) for c in "247CTF{"]

print("Brute forcing key (65536 possibilities)...")

# Brute force the key
found = False
for a in range(256):
    for b in range(256):
        key = [a, b] * 4

        # Try encrypting known plaintext (first 8 bytes padded)
        test_plain = known + [0] * (8 - len(known))
        test_enc = r_encrypt(test_plain, key)

        # Check if first 7 bytes match
        if test_enc[:7] == encrypted[:7]:
            print(f"Found key: a={a}, b={b}")
            print(f"Key bytes: {key}")

            # Decrypt the entire message
            decrypted = r_decrypt(encrypted, key)
            flag = ''.join([chr(c) for c in decrypted])
            print(f"Decrypted: {flag}")
            found = True
            break
    if found:
        break

if not found:
    print("Key not found!")
