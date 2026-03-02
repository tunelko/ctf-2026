#!/usr/bin/env python3
"""
Challenge: Cornflakev3.5
Category:  rev
Platform:  Srdnlen CTF 2026 Quals

VM bytecode interpreter solver.
Traces VM building z3 BitVec expressions directly.
"""
from z3 import *

bytecode_hex = "550c0f10550c070d0e0f01730c0f03040205550c0f10540c070d0e0f01550c0f10560c070f03080e0f01550c0f10570c070f01550c0f10570c070d0e0f030e09100e03070f01170c0f03040205550c0f10560c070d0e0f016e0c0f03040205550c0f10510c070d0e0f01550c0f10500c070d0e0f03080e0f01d10c0f03040205210c0d0e0f01550c0f10560c070f03080e0f01550c0f10570c070f01150c0d0e0f030e09100e03070f01ea0c0f03040205550c0f10560c070d0e0f01550c0f10530c070d0e0f03040f01550c0f10540c070f03040205550c0f105d0c070d0e0f01550c0f10570c0703110f01e40c0f03040205170c0d0e0f01550c0f10590c070d0e0f030e09100e0f01550c0f10470c070d0e03070f01770c0f03040205550c0f10510c070f01140c0d0e03120f01550c0f105a0c070d0e03070f01550c0f105f0c070d0e0f03080e0f01be0c0f03040205550c0f10440c070d0e0f01550c0f105e0c070d0e0f030e09100e0f011d0c0d0e03070f01580c0f03040205550c0f10510c070f01550c0f10520c070d0e03120f01550c0f10450c070d0e03070f011c0c0d0e0f03080e0f01de0c0f03040205550c0f10580c070d0e0f01550c0f105b0c070d0e0f03080e0f01030e0f01820c0f03040205550c0f105c0c070d0e0f01550c0f10500c070f01030e030f0e10120f01550c0f10500c0703110f01550c0f105c0c070d0e0f030e09100e0f01550c0f10540c070f03040205300c0f01160c0d0e0f030e09100e0d0e0f01720c0f03040205160c0d0e0f01180c0d0e0f03080e0f01030e0f01640c0f030402051b0c0d0e0f01550c0f10560c0703110f01190c0d0e0f011a0c0d0e0f01550c0f10570c0703110f03080e0f030e09100e0f01760c0f030402051e0c0d0e0f011f0c0d0e0f03080e0f01200c0d0e0f03080e0f01030e0f01d90c0f03040205"

bc = bytes.fromhex(bytecode_hex)
FLAG_LEN = 34

# z3 BitVec variables for password
pz = [BitVec(f'p{i}', 32) for i in range(FLAG_LEN)]

known = {
    0: ord('s'), 1: ord('r'), 2: ord('d'), 3: ord('n'),
    4: ord('l'), 5: ord('e'), 6: ord('n'), 7: ord('{'),
    33: ord('}')
}

# VM state using z3 expressions directly
BV = lambda x: BitVecVal(x, 32) if isinstance(x, int) else x

a = BV(0); b = BV(0); c = BV(0)
stack = []; ip = 0
bc_arr = list(bc)
constraints = []
check_num = 0

while ip < len(bc_arr):
    opcode = bc_arr[ip]

    if opcode > 0x12:
        pass  # NOP / data
    elif opcode == 0x00 or opcode == 0x06:
        pass
    elif opcode == 0x01:
        stack.append(c)
    elif opcode == 0x02:
        if ip + 1 < len(bc_arr):
            bc_arr[ip + 1] += 1
    elif opcode == 0x03:
        if stack:
            b = stack.pop()
    elif opcode == 0x04:
        constraints.append((simplify(b), simplify(c), check_num))
        a = BV(1)
        check_num += 1
    elif opcode == 0x05:
        print(f"HALT @ ip={ip}")
        break
    elif opcode == 0x07:
        a = a ^ b
    elif opcode == 0x08:
        b = b + c
    elif opcode == 0x09:
        c = c - a
    elif opcode == 0x0a:
        # b = password[ip - a]
        sa = simplify(a)
        if is_bv_value(sa):
            idx = ip - sa.as_long()
            if 0 <= idx < FLAG_LEN:
                b = pz[idx]
    elif opcode == 0x0b:
        sa = simplify(a)
        if is_bv_value(sa):
            idx = ip + sa.as_long()
            if 0 <= idx < FLAG_LEN:
                b = pz[idx]
    elif opcode == 0x0c:
        a = BV(bc_arr[ip - 1] if ip > 0 else 0)
    elif opcode == 0x0d:
        sa = simplify(a)
        if is_bv_value(sa):
            idx = sa.as_long()
            if idx >= 0x80000000:
                idx -= 0x100000000
            if 0 <= idx < FLAG_LEN:
                b = pz[idx]
        else:
            # Symbolic index
            result = BV(0)
            for i in range(FLAG_LEN - 1, -1, -1):
                result = If(a == i, pz[i], result)
            b = result
    elif opcode == 0x0e:
        a = b
    elif opcode == 0x0f:
        c = a
    elif opcode == 0x10:
        b = c
    elif opcode == 0x11:
        a = a * b
    elif opcode == 0x12:
        a = UDiv(a, b)

    ip += 1

print(f"[*] Total checks: {check_num}")

# Print constraints
for bv, cv, num in constraints:
    print(f"  CHECK {num}: {bv} == {cv}")

# ===== Solve =====
solver = Solver()

# Known chars
for idx, val in known.items():
    solver.add(pz[idx] == val)

# All chars are printable ASCII (no sign extension issues)
for i in range(FLAG_LEN):
    solver.add(pz[i] >= 0x20, pz[i] <= 0x7e)

# VM constraints
for bv, cv, num in constraints:
    solver.add(bv == cv)

# Flag charset: lowercase + digits + underscore for inner flag
for i in range(8, 33):
    solver.add(Or(
        And(pz[i] >= ord('a'), pz[i] <= ord('z')),
        And(pz[i] >= ord('0'), pz[i] <= ord('9')),
        pz[i] == ord('_')
    ))

print(f"\n[*] Solving with tight charset (a-z, 0-9, _)...")
result = solver.check()
if result == sat:
    m = solver.model()
    flag = "".join(chr(m.eval(pz[i], model_completion=True).as_long() & 0xff) for i in range(FLAG_LEN))
    print(f"[+] Flag: {flag}")

    # Check uniqueness
    solver.push()
    solver.add(Or([pz[i] != m.eval(pz[i], model_completion=True) for i in range(8, 33)]))
    count = 1
    flags = [flag]
    while solver.check() == sat and count < 30:
        m2 = solver.model()
        f2 = "".join(chr(m2.eval(pz[i], model_completion=True).as_long() & 0xff) for i in range(FLAG_LEN))
        flags.append(f2)
        count += 1
        solver.add(Or([pz[i] != m2.eval(pz[i], model_completion=True) for i in range(8, 33)]))

    if count == 1:
        print("[+] UNIQUE solution!")
    else:
        print(f"[*] {count} solutions found:")
        for i, f in enumerate(flags):
            print(f"  [{i:2d}] {f}")
    solver.pop()
else:
    print(f"[-] {result} with tight charset")

    # Try broader charset: lowercase + uppercase + digits + underscore + special
    solver2 = Solver()
    for idx, val in known.items():
        solver2.add(pz[idx] == val)
    for i in range(FLAG_LEN):
        solver2.add(pz[i] >= 0x20, pz[i] <= 0x7e)
    for bv, cv, num in constraints:
        solver2.add(bv == cv)

    print("[*] Trying all printable ASCII...")
    if solver2.check() == sat:
        m = solver2.model()
        flag = "".join(chr(m.eval(pz[i], model_completion=True).as_long() & 0xff) for i in range(FLAG_LEN))
        print(f"[+] Flag (relaxed): {flag}")

        # Count solutions
        solver2.add(Or([pz[i] != m.eval(pz[i], model_completion=True) for i in range(8, 33)]))
        count = 1
        flags = [flag]
        while solver2.check() == sat and count < 10:
            m2 = solver2.model()
            f2 = "".join(chr(m2.eval(pz[i], model_completion=True).as_long() & 0xff) for i in range(FLAG_LEN))
            flags.append(f2)
            count += 1
            solver2.add(Or([pz[i] != m2.eval(pz[i], model_completion=True) for i in range(8, 33)]))
        print(f"[*] {count} solutions found (limit 10):")
        for i, f in enumerate(flags):
            print(f"  [{i:2d}] {f}")
