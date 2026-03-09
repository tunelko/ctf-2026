#!/usr/bin/env python3
"""
Solver for locked-in (diceCTF 2026 rev)

Custom VM with 16 threads, futex-based IPC channels.
State: packed = high32 * 2^32 + low32
FUTEX_WAKE returns W=1.

Operations (from 2-bit pairs of transformed byte):
  0: h--  |  1: h++  |  2: l*=2 (overflow carries to h)  |  3: l//=2

Per-operation check: expected[new_h] & new_l == 0 → accepted, else rejected (no change).

Key insight: l is always a power of 2 or 0 (starts as 2^17, only shifted).
State space: 16 h values * 33 l values = 528 states. BFS is instant.
"""

from collections import defaultdict

def transform_char(c):
    x = c
    x = (x ^ 0x5A) & 0xFF
    x = ((x << 1) | (x >> 7)) & 0xFF
    x = (x ^ 0x5A) & 0xFF
    if x & 1:
        x = (x ^ (2 * x)) & 0xFF
    else:
        x = (x ^ 0xFE) & 0xFF
    x = (x ^ 0x5A) & 0xFF
    return x

# Expected values with W=1
EXPECTED = [
    0xFFFFFFFF, 0x8000C303, 0xAEEE9859, 0xA8AAA725,
    0xA8ACA889, 0xA8AA8261, 0xAEEAFF2F, 0xA00088A9,
    0x9FFF2229, 0xD10255E5, 0x95AA8813, 0xD1282ACB,
    0x95654AA9, 0xA555AAB5, 0x88042205, 0xFFFFFFFF,
]

def apply_4ops(h, l_bit, tb):
    """Apply 4 operations from transformed byte with AND checks.
    l_bit: -1 means l=0, otherwise l = 2^l_bit.
    Returns (new_h, new_l_bit)."""
    # Convert l_bit to actual l value
    l = 0 if l_bit < 0 else (1 << l_bit)
    h_cur, l_cur = h, l

    for i in range(4):
        pair = (tb >> (2 * i)) & 3

        if pair == 0:  # h--
            new_h = h_cur - 1
            new_l = l_cur
        elif pair == 1:  # h++
            new_h = h_cur + 1
            new_l = l_cur
        elif pair == 2:  # l *= 2
            if l_cur == 0:
                new_h, new_l = h_cur, 0
            elif l_cur == (1 << 31):
                # Overflow: l becomes 0, h increments
                new_h = h_cur + 1
                new_l = 0
            else:
                new_h = h_cur
                new_l = l_cur * 2
        elif pair == 3:  # l //= 2
            new_h = h_cur
            new_l = l_cur // 2

        # AND check on new state
        if 0 <= new_h <= 15 and (EXPECTED[new_h] & new_l) == 0:
            h_cur, l_cur = new_h, new_l  # accepted
        # else: rejected, state unchanged

    # Convert back to l_bit
    if l_cur == 0:
        new_l_bit = -1
    else:
        new_l_bit = l_cur.bit_length() - 1
        assert l_cur == (1 << new_l_bit), f"l={l_cur} is not a power of 2!"

    return h_cur, new_l_bit

def solve():
    # Precompute transforms
    tb_to_chars = {}
    for c in range(0x20, 0x7f):
        tb = transform_char(c)
        if tb not in tb_to_chars:
            tb_to_chars[tb] = []
        tb_to_chars[tb].append(c)
    unique_tbs = sorted(tb_to_chars.keys())
    print(f"[*] {len(unique_tbs)} unique transforms from 95 printable chars")

    # Process prefix "dice{"
    h, l_bit = 4, 17  # Start: h=4, l=0x20000=2^17
    for c in b"dice{":
        tb = transform_char(c)
        h, l_bit = apply_4ops(h, l_bit, tb)
    print(f"[*] After prefix 'dice{{': h={h}, l_bit={l_bit} (l={'0' if l_bit<0 else hex(1<<l_bit)})")

    # Target after suffix "}"
    suffix_tb = transform_char(ord('}'))
    target_h, target_l_bit = 14, 1  # l=2 = 2^1

    # BFS: 24 inner chars
    # State: (h, l_bit) where h in [0,15], l_bit in [-1, 0, 1, ..., 31]
    # Layer 0 = after prefix, Layer 24 = before suffix

    inner_len = 24
    # Forward BFS: layer by layer
    # current_states[state] = (prev_state, tb_used)
    current = {(h, l_bit): None}  # initial state, no predecessor

    # Store all layers for path reconstruction
    layers = [current]

    for step in range(inner_len):
        next_states = {}
        for (ch, cl), _ in current.items():
            for tb in unique_tbs:
                nh, nl = apply_4ops(ch, cl, tb)
                state = (nh, nl)
                if state not in next_states:
                    next_states[state] = ((ch, cl), tb)
        current = next_states
        layers.append(current)
        print(f"  Step {step+1}: {len(current)} reachable states")

    # Now apply suffix to each state in layer 24 and check for target
    print(f"\n[*] Checking suffix '}}' (tb=0x{suffix_tb:02x})...")
    winning_state = None
    for (ch, cl), pred in current.items():
        fh, fl = apply_4ops(ch, cl, suffix_tb)
        if fh == target_h and fl == target_l_bit:
            winning_state = (ch, cl)
            print(f"[+] Found! State before suffix: h={ch}, l_bit={cl}")
            break

    if winning_state is None:
        print("[-] No solution found!")
        # Debug: show which states are reachable at each layer
        return None

    # Reconstruct path
    path_tbs = []
    state = winning_state
    for step in range(inner_len, 0, -1):
        pred_state, tb_used = layers[step][state]
        path_tbs.append(tb_used)
        state = pred_state
    path_tbs.reverse()

    # Convert to characters
    inner_chars = []
    for tb in path_tbs:
        inner_chars.append(tb_to_chars[tb][0])  # pick first char with this transform

    flag = b"dice{" + bytes(inner_chars) + b"}"
    print(f"\n[+] Flag: {flag.decode()}")

    # Verify
    h, l_bit = 4, 17
    for c in flag:
        tb = transform_char(c)
        h, l_bit = apply_4ops(h, l_bit, tb)
    l_final = 0 if l_bit < 0 else (1 << l_bit)
    assert h == 14 and l_final == 2, f"Verification failed! h={h}, l={l_final}"
    print("[+] Verified!")

    return flag

if __name__ == "__main__":
    solve()
