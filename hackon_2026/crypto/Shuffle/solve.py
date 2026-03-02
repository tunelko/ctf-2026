#!/usr/bin/env python3
from pwn import *
import ast

HOST, PORT = "0.cloud.chals.io", 16316
context.log_level = 'info'

# ── MT19937 state recovery ──────────────────────────────────────────────────

def undo_right_xor(y, shift):
    result = y
    for _ in range(32 // shift):
        result = y ^ (result >> shift)
    return result & 0xffffffff

def undo_left_xor(y, shift, mask):
    result = 0
    for i in range(32):
        bit = (y >> i) & 1
        if i >= shift:
            bit ^= ((result >> (i - shift)) & 1) & ((mask >> i) & 1)
        result |= bit << i
    return result

def untemper(y):
    """Reverse the MT19937 tempering transform."""
    y = undo_right_xor(y, 18)
    y = undo_left_xor(y, 15, 0xefc60000)
    y = undo_left_xor(y, 7,  0x9d2c5680)
    y = undo_right_xor(y, 11)
    return y & 0xffffffff

def extract_mt_words(hints):
    """
    Each hint = int.from_bytes(random.randbytes(8), 'big')
    randbytes(8) packs two 32-bit MT words as little-endian bytes.
    int.from_bytes(..., 'big') reverses those bytes.
    So: w0 = int.from_bytes(n.to_bytes(8,'big')[0:4], 'little')
        w1 = int.from_bytes(n.to_bytes(8,'big')[4:8], 'little')
    """
    words = []
    for n in hints:
        raw = n.to_bytes(8, 'big')
        w0 = int.from_bytes(raw[0:4], 'little')
        w1 = int.from_bytes(raw[4:8], 'little')
        words.append(w0)
        words.append(w1)
    return words

def recover_random(mt_words):
    """Recover RNG state from 624 consecutive 32-bit MT outputs."""
    import random
    recovered = [untemper(w) for w in mt_words[:624]]
    r = random.Random()
    r.setstate((3, tuple(recovered + [624]), None))
    return r

# ── Main exploit ────────────────────────────────────────────────────────────

def exploit():
    io = remote(HOST, PORT)
    io.recvuntil(b'Toma una pista\r\n')

    # Read hint list
    hint_line = io.recvline().decode().strip()
    hints = ast.literal_eval(hint_line)
    log.info(f'Got {len(hints)} hints')

    # Extract MT words (1000 words from 500 hints, need 624)
    mt_words = extract_mt_words(hints)
    log.info(f'Extracted {len(mt_words)} MT words')

    # Recover RNG state from first 624 words
    r = recover_random(mt_words)

    # Fast-forward through remaining hints (words 624..999)
    remaining = len(mt_words) - 624
    for _ in range(remaining):
        r.getrandbits(32)
    log.info(f'Fast-forwarded {remaining} words')

    # Read the 11-element list from server
    io.recvuntil(b'La lista es esta:\r\n')
    list_line = io.recvline().decode().strip()
    a_original = ast.literal_eval(list_line)
    log.info(f'Original list: {a_original}')

    # Predict the same 11 getrandbits(32) calls
    a_predicted = [r.getrandbits(32) for _ in range(11)]

    if a_predicted != a_original:
        log.error(f'List prediction WRONG!\n  predicted={a_predicted}\n  actual={a_original}')
        io.close()
        return False

    log.success('List prediction correct! Simulating shuffle...')

    # Simulate random.shuffle(a)
    a = a_predicted.copy()
    for i in range(len(a) - 1, 0, -1):
        j = r._randbelow(i + 1)
        a[i], a[j] = a[j], a[i]

    log.info(f'Predicted shuffled list: {a}')

    # Send prediction
    io.recvuntil(b'predicci')  # handle UTF-8 ó
    io.recvuntil(b': ')
    prediction = ' '.join(map(str, a))
    io.sendline(prediction.encode())

    result = io.recvall(timeout=5)
    log.success(f'Server response: {result.decode(errors="replace").strip()}')
    io.close()
    return True

if __name__ == '__main__':
    exploit()
