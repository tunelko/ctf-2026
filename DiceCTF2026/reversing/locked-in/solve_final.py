#!/usr/bin/env python3
"""
Solver for locked-in (diceCTF 2026 rev)

Custom VM with 16 threads, futex-based IPC channels.
- Each flag char is XORed with a per-position key (sub_1463)
- Chars are sent to the processor in REVERSE order
- Transform pipeline: XOR 0x5A, ROL1, XOR 0x5A, conditional XOR, XOR 0x5A
- Each transformed byte = 4 operations (2-bit pairs)
- Operations: 0=h--, 1=h++, 2=l*=2, 3=l//=2
- Check: expected[new_h] & new_l == 0 → accepted
- Start: h=4, l=0x20000 (2^17)
- Target: h=14, l=2 (2^1)
"""

from collections import defaultdict

# Per-position XOR keys (extracted from sub_1463 emulation with W=1)
XOR_KEYS = [237, 147, 150, 156, 205, 207, 115, 85, 41, 22,
            159, 196, 170, 155, 75, 246, 180, 122, 177, 230,
            252, 218, 150, 186, 145, 87, 65, 30, 81, 145]

# Expected values (W=1, confirmed via GDB)
EXPECTED = [
    0xFFFFFFFF, 0x8000C303, 0xAEEE9859, 0xA8AAA725,
    0xA8ACA889, 0xA8AA8261, 0xAEEAFF2F, 0xA00088A9,
    0x9FFF2229, 0xD10255E5, 0x95AA8813, 0xD1282ACB,
    0x95654AA9, 0xA555AAB5, 0x88042205, 0xFFFFFFFF,
]

def transform_char(c):
    """Apply the 5-stage transform pipeline (threads r, n, r, >, r)."""
    x = c
    x = (x ^ 0x5A) & 0xFF        # XOR 0x5A
    x = ((x << 1) | (x >> 7)) & 0xFF  # ROL 1
    x = (x ^ 0x5A) & 0xFF        # XOR 0x5A
    if x & 1:
        x = (x ^ (2 * x)) & 0xFF  # odd: XOR with 2*x
    else:
        x = (x ^ 0xFE) & 0xFF     # even: XOR with 0xFE
    x = (x ^ 0x5A) & 0xFF        # XOR 0x5A
    return x

def apply_4ops(h, l_bit, tb):
    """Apply 4 operations from transformed byte.
    l_bit: -1 means l=0, otherwise l = 2^l_bit.
    Returns (new_h, new_l_bit)."""
    l = 0 if l_bit < 0 else (1 << l_bit)

    for i in range(4):
        pair = (tb >> (2 * i)) & 3
        if pair == 0:    # h--
            new_h, new_l = h - 1, l
        elif pair == 1:  # h++
            new_h, new_l = h + 1, l
        elif pair == 2:  # l *= 2
            if l == 0:
                new_h, new_l = h, 0
            elif l >= (1 << 31):
                new_h, new_l = h + 1, 0
            else:
                new_h, new_l = h, l * 2
        elif pair == 3:  # l //= 2
            new_h, new_l = h, l // 2

        if 0 <= new_h <= 15 and (EXPECTED[new_h] & new_l) == 0:
            h, l = new_h, new_l

    if l == 0:
        return h, -1
    else:
        return h, l.bit_length() - 1

def solve():
    # Build mapping: for each possible XORed byte (0-255), what transform does it produce?
    # We need to find, for each processing step, what original flag char works.

    # Processing order: flag chars are reversed, then XORed, then transformed.
    # Step i (0-indexed) processes: flag[29-i] ^ XOR_KEYS[29-i]
    # So: transform_char(flag[29-i] ^ XOR_KEYS[29-i]) = tb
    # For flag char c at position p = 29-i: tb = transform_char(c ^ XOR_KEYS[p])

    # For each processing step i, the flag position is pos = 29-i
    # The XOR key is XOR_KEYS[pos]
    # For flag char c (printable ASCII 0x20-0x7e):
    #   xored = c ^ XOR_KEYS[pos]
    #   tb = transform_char(xored)

    # BFS: 30 steps total (not just 24 inner chars!)
    # Flag = 30 chars, no prefix/suffix constraint (the full flag goes through the pipeline)

    START_H, START_L = 4, 17  # h=4, l=2^17
    TARGET_H, TARGET_L = 14, 1  # h=14, l=2^1=2

    # For each step, precompute the set of (tb, flag_char) pairs
    steps = []
    for step in range(30):
        pos = 29 - step  # flag position
        key = XOR_KEYS[pos]
        tb_to_chars = {}
        for c in range(0x20, 0x7f):  # printable ASCII
            xored = c ^ key
            tb = transform_char(xored)
            if tb not in tb_to_chars:
                tb_to_chars[tb] = []
            tb_to_chars[tb].append(c)
        steps.append(tb_to_chars)

    # Get unique tbs per step
    print(f"[*] Start: h={START_H}, l_bit={START_L}")
    print(f"[*] Target: h={TARGET_H}, l_bit={TARGET_L}")

    # Forward BFS
    current = {(START_H, START_L): None}
    layers = [current]

    for step in range(30):
        next_states = {}
        unique_tbs = steps[step].keys()
        for (ch, cl), _ in current.items():
            for tb in unique_tbs:
                nh, nl = apply_4ops(ch, cl, tb)
                state = (nh, nl)
                if state not in next_states:
                    next_states[state] = ((ch, cl), tb)
        current = next_states
        layers.append(current)
        if (step + 1) % 5 == 0 or step == 29:
            print(f"  Step {step+1}/30: {len(current)} reachable states")

    # Check if target is reachable
    target = (TARGET_H, TARGET_L)
    if target not in current:
        print(f"[-] Target state {target} not reachable!")
        print(f"    Reachable states at h={TARGET_H}:")
        for (h, l) in sorted(current.keys()):
            if h == TARGET_H:
                print(f"      h={h}, l_bit={l}")
        return None

    print(f"[+] Target state {target} is reachable!")

    # Reconstruct path
    path_tbs = []
    state = target
    for step in range(30, 0, -1):
        pred_state, tb_used = layers[step][state]
        path_tbs.append(tb_used)
        state = pred_state
    path_tbs.reverse()

    # Convert to flag characters
    flag_chars = [0] * 30
    for step in range(30):
        tb = path_tbs[step]
        pos = 29 - step  # flag position
        chars = steps[step][tb]
        flag_chars[pos] = chars[0]  # pick first printable char

    flag = bytes(flag_chars)
    print(f"\n[+] Flag: {flag.decode()}")

    # Verify
    xored = [flag[i] ^ XOR_KEYS[i] for i in range(30)]
    processing_order = list(reversed(xored))
    h, l = 4, 1 << 17
    for xc in processing_order:
        tb = transform_char(xc)
        h, l = apply_4ops_actual(h, l, tb)
    assert h == 14 and l == 2, f"Verification failed! h={h}, l={l}"
    print("[+] Verified!")
    return flag

def apply_4ops_actual(h, l, tb):
    """Apply 4 operations using actual l values (not l_bit)."""
    for i in range(4):
        pair = (tb >> (2 * i)) & 3
        if pair == 0:
            new_h, new_l = h - 1, l
        elif pair == 1:
            new_h, new_l = h + 1, l
        elif pair == 2:
            if l == 0:
                new_h, new_l = h, 0
            elif l >= (1 << 31):
                new_h, new_l = h + 1, 0
            else:
                new_h, new_l = h, l * 2
        elif pair == 3:
            new_h, new_l = h, l // 2

        if 0 <= new_h <= 15 and (EXPECTED[new_h] & new_l) == 0:
            h, l = new_h, new_l
    return h, l

if __name__ == "__main__":
    solve()
