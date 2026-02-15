#!/usr/bin/env python3
"""
Solve challenge.hiero - with flag format constraints
"""
from z3 import *

# Extracted XOR comparisons
comparisons = [
    (6, 7, 0xd8), (7, 8, 0x9c), (8, 9, 0xa6), (9, 10, 0xa6),
    (10, 11, 0x64), (11, 12, 0x98), (12, 13, 0xc7), (13, 14, 0xd5),
    (14, 15, 0xe3), (15, 16, 0xcc), (16, 17, 0x90), (17, 18, 0x9f),
    (18, 19, 0xd1), (19, 20, 0x96), (20, 21, 0xa3), (21, 22, 0xe4),
    (22, 23, 0xa5), (23, 24, 0x61), (24, 25, 0x9e),
    # Cross comparisons
    (6, 10, 0xa4), (8, 15, 0xa1), (12, 20, 0x9b),
    (15, 23, 0x9e), (7, 18, 0xd6),
]

solver = Solver()
v = [BitVec(f'v{i}', 8) for i in range(27)]

# Flag format: 0xfun{...}
known = {
    0: ord('0'),  # 0x30
    1: ord('x'),  # 0x78
    2: ord('f'),  # 0x66
    3: ord('u'),  # 0x75
    4: ord('n'),  # 0x6E
    5: ord('{'),  # 0x7B
    26: ord('}'), # 0x7D
}

for idx, val in known.items():
    solver.add(v[idx] == val)

# XOR constraints
for a, b, expected in comparisons:
    solver.add(v[a] ^ v[b] == expected)

# Printable for vars 6-25 (flag content)
for i in range(6, 26):
    solver.add(v[i] >= 0x20, v[i] <= 0x7e)

if solver.check() == sat:
    model = solver.model()
    flag = ''
    for i in range(27):
        val = model[v[i]].as_long()
        flag += chr(val)
    print(f"[+] Flag: {flag}")
else:
    print("[-] No solution with printable constraint")
    # Try without printable constraint
    solver2 = Solver()
    v2 = [BitVec(f'v{i}', 8) for i in range(27)]
    for idx, val in known.items():
        solver2.add(v2[idx] == val)
    for a, b, expected in comparisons:
        solver2.add(v2[a] ^ v2[b] == expected)

    if solver2.check() == sat:
        model = solver2.model()
        flag = ''
        for i in range(27):
            val = model[v2[i]].as_long()
            flag += chr(val) if 32 <= val < 127 else f'\\x{val:02x}'
        print(f"[+] Flag (without printable): {flag}")

        # Check how many solutions
        print("\n[*] Searching for more solutions...")
        for extra in range(3):
            solver2.add(Or([v2[i] != model[v2[i]] for i in range(27)]))
            if solver2.check() == sat:
                model = solver2.model()
                flag2 = ''
                for i in range(27):
                    val = model[v2[i]].as_long()
                    flag2 += chr(val) if 32 <= val < 127 else f'\\x{val:02x}'
                print(f"    Another: {flag2}")
            else:
                print(f"    Only {extra+1} solution(s)")
                break
    else:
        print("[-] No solution even without printable")
        print("[*] Trying without flag format...")
        solver3 = Solver()
        v3 = [BitVec(f'v{i}', 8) for i in range(27)]
        for a, b, expected in comparisons:
            solver3.add(v3[a] ^ v3[b] == expected)
        # Just try to find any solution
        if solver3.check() == sat:
            model = solver3.model()
            vals = [model[v3[i]].as_long() for i in range(27)]
            print(f"    Vals: {[hex(x) for x in vals]}")
