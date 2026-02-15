#!/usr/bin/env python3
"""BitStorm solver - GF(2) linear algebra approach
All PRNG operations are linear over GF(2), so we can recover the seed
from outputs using Gaussian elimination."""
import sys, time

MASK64 = (1 << 64) - 1
N_VARS = 2048  # 32 words * 64 bits

# --- Symbolic word operations (64 dependency vectors of N_VARS bits) ---

def sw_zero():
    return [0] * 64

def sw_xor(a, b):
    return [a[i] ^ b[i] for i in range(64)]

def sw_lshift(a, k):
    """Logical left shift by k bits"""
    if k == 0: return list(a)
    if k >= 64: return sw_zero()
    r = [0] * 64
    for i in range(k, 64):
        r[i] = a[i - k]
    return r

def sw_rshift(a, k):
    """Logical right shift by k bits"""
    if k == 0: return list(a)
    if k >= 64: return sw_zero()
    r = [0] * 64
    for i in range(64 - k):
        r[i] = a[i + k]
    return r

def sw_rotl(a, k):
    """Rotate left by k bits"""
    k = k % 64
    if k == 0: return list(a)
    return [a[(i - k) % 64] for i in range(64)]

def sw_rotr(a, k):
    """Rotate right by k bits"""
    k = k % 64
    if k == 0: return list(a)
    return [a[(i + k) % 64] for i in range(64)]


# --- Build initial symbolic state ---

def build_initial_state():
    """state[w] bit b = seed_int bit (64*(31-w) + b)"""
    sym_state = []
    for w in range(32):
        word = [0] * 64
        for b in range(64):
            var_idx = 64 * (31 - w) + b
            word[b] = 1 << var_idx
        sym_state.append(word)
    return sym_state


# --- Symbolic PRNG step ---

def sym_next(sym_state):
    s = sym_state
    taps = [0, 1, 3, 7, 13, 22, 28, 31]

    new_val = sw_zero()
    for i in taps:
        val = s[i]
        # mixed = val ^ (val << 11) ^ (val >> 7)
        mixed = sw_xor(val, sw_xor(sw_lshift(val, 11), sw_rshift(val, 7)))
        # rotate left by (i*3) % 64
        rot = (i * 3) % 64
        if rot > 0:
            mixed = sw_rotl(mixed, rot)
        new_val = sw_xor(new_val, mixed)

    # new_val ^= (s[31] >> 13) ^ (s[31] << 5)
    extra = sw_xor(sw_rshift(s[31], 13), sw_lshift(s[31], 5))
    new_val = sw_xor(new_val, extra)

    # Shift state
    new_state = s[1:] + [new_val]

    # Compute output
    out = sw_zero()
    for i in range(32):
        if i % 2 == 0:
            out = sw_xor(out, new_state[i])
        else:
            out = sw_xor(out, sw_rotr(new_state[i], 2))

    return new_state, out


# --- Gaussian elimination over GF(2) ---

def gauss_gf2(equations, n_vars):
    """Solve system over GF(2).
    equations: list of (coeff_int, constant_bit)
    Returns solution as n_vars-bit integer."""
    aug = n_vars  # augmented bit position

    # Build augmented matrix rows
    matrix = []
    for coeff, const in equations:
        row = coeff
        if const:
            row |= (1 << aug)
        matrix.append(row)

    n_rows = len(matrix)
    pivot_row_idx = {}  # col -> row index in matrix
    cur = 0  # next available row position

    t0 = time.time()
    for col in range(n_vars):
        # Find pivot row
        found = -1
        for r in range(cur, n_rows):
            if matrix[r] & (1 << col):
                found = r
                break

        if found == -1:
            continue  # free variable

        # Swap to position cur
        matrix[cur], matrix[found] = matrix[found], matrix[cur]
        pivot_row_idx[col] = cur
        pivot_val = matrix[cur]

        # Eliminate col from all other rows
        for r in range(n_rows):
            if r != cur and matrix[r] & (1 << col):
                matrix[r] ^= pivot_val

        cur += 1
        if cur % 512 == 0:
            elapsed = time.time() - t0
            print(f"  Gauss: {cur}/{n_vars} pivots ({elapsed:.1f}s)", flush=True)

    elapsed = time.time() - t0
    print(f"  Gauss done: {cur} pivots found in {elapsed:.1f}s")

    if cur < n_vars:
        print(f"  WARNING: system underdetermined ({n_vars - cur} free variables)")

    # Extract solution
    solution = 0
    for col in range(n_vars):
        if col in pivot_row_idx:
            row = matrix[pivot_row_idx[col]]
            if row & (1 << aug):
                solution |= (1 << col)

    return solution


# --- Concrete PRNG (for verification) ---

def run_prng(seed_int, n_outputs):
    state = []
    for i in range(32):
        shift = 64 * (31 - i)
        state.append((seed_int >> shift) & MASK64)

    outputs = []
    for _ in range(n_outputs):
        s = state
        taps = [0, 1, 3, 7, 13, 22, 28, 31]
        new_val = 0
        for i in taps:
            val = s[i]
            mixed = val ^ ((val << 11) & MASK64) ^ (val >> 7)
            rot = (i * 3) % 64
            mixed = ((mixed << rot) | (mixed >> (64 - rot))) & MASK64
            new_val ^= mixed
        new_val ^= (s[-1] >> 13) ^ ((s[-1] << 5) & MASK64)
        new_val &= MASK64
        state = s[1:] + [new_val]

        out = 0
        for i in range(32):
            if i % 2 == 0:
                out ^= state[i]
            else:
                val = state[i]
                out ^= ((val >> 2) | (val << 62)) & MASK64
        outputs.append(out)

    return outputs


def solve(target_outputs):
    """Given list of PRNG outputs, recover the seed."""
    n_steps = len(target_outputs)

    print(f"Building symbolic state ({N_VARS} variables)...")
    sym_state = build_initial_state()

    print(f"Running symbolic simulation ({n_steps} steps)...")
    equations = []
    t0 = time.time()
    for step in range(n_steps):
        sym_state, sym_out = sym_next(sym_state)
        actual = target_outputs[step]
        for b in range(64):
            coeff = sym_out[b]
            const = (actual >> b) & 1
            if coeff != 0:
                equations.append((coeff, const))
        if (step + 1) % 10 == 0:
            print(f"  Step {step+1}/{n_steps} ({time.time()-t0:.1f}s)", flush=True)

    print(f"Collected {len(equations)} equations in {time.time()-t0:.1f}s")

    print("Solving with Gaussian elimination...")
    solution = gauss_gf2(equations, N_VARS)

    return solution


# --- Main ---

def main():
    # === TEST PHASE ===
    print("=" * 60)
    print("PHASE 1: Testing with known flag")
    print("=" * 60)

    test_content = b"test_flag_XYZ_1234567890_ABCDEF"
    test_content = test_content.ljust(256, b'\0')
    test_seed = int.from_bytes(test_content, 'big')
    test_outputs = run_prng(test_seed, 60)

    print(f"Test seed first word: {test_seed >> (64*31):#018x}")
    print(f"Test output[0]: {test_outputs[0]}")

    recovered = solve(test_outputs)

    print("\nVerifying test solution...")
    check_outputs = run_prng(recovered, 60)
    if check_outputs == test_outputs:
        print("TEST PASSED! Solver is correct.")
        recovered_bytes = recovered.to_bytes(256, 'big')
        recovered_text = recovered_bytes.rstrip(b'\0').decode('ascii', errors='replace')
        print(f"Recovered text: {recovered_text}")
    else:
        print("TEST FAILED!")
        # Debug: compare seeds
        print(f"Expected seed: {test_seed:#0{514}x}")
        print(f"Got seed:      {recovered:#0{514}x}")
        diff = test_seed ^ recovered
        print(f"Diff bits: {bin(diff).count('1')}")
        # Check first few outputs
        for i in range(min(5, len(check_outputs))):
            match = "OK" if check_outputs[i] == test_outputs[i] else "MISMATCH"
            print(f"  Output[{i}]: got={check_outputs[i]}, exp={test_outputs[i]} {match}")
        sys.exit(1)

    # === SOLVE PHASE ===
    print("\n" + "=" * 60)
    print("PHASE 2: Solving real challenge")
    print("=" * 60)

    real_outputs = [
        11329270341625800450, 14683377949987450496, 11656037499566818711,
        14613944493490807838, 370532313626579329, 5006729399082841610,
        8072429272270319226, 3035866339305997883, 8753420467487863273,
        15606411394407853524, 5092825474622599933, 6483262783952989294,
        15380511644426948242, 13769333495965053018, 5620127072433438895,
        6809804883045878003, 1965081297255415258, 2519823891124920624,
        8990634037671460127, 3616252826436676639, 1455424466699459058,
        2836976688807481485, 11291016575083277338, 1603466311071935653,
        14629944881049387748, 3844587940332157570, 584252637567556589,
        10739738025866331065, 11650614949586184265, 1828791347803497022,
        9101164617572571488, 16034652114565169975, 13629596693592688618,
        17837636002790364294, 10619900844581377650, 15079130325914713229,
        5515526762186744782, 1211604266555550739, 11543408140362566331,
        18425294270126030355, 2629175584127737886, 6074824578506719227,
        6900475985494339491, 3263181255912585281, 12421969688110544830,
        10785482337735433711, 10286647144557317983, 15284226677373655118,
        9365502412429803694, 4248763523766770934, 13642948918986007294,
        3512868807899248227, 14810275182048896102, 1674341743043240380,
        28462467602860499, 1060872896572731679, 13208674648176077254,
        14702937631401007104, 5386638277617718038, 8935128661284199759
    ]

    solution = solve(real_outputs)

    print("\nVerifying real solution...")
    check = run_prng(solution, 60)
    if check == real_outputs:
        print("VERIFICATION PASSED!")
        sol_bytes = solution.to_bytes(256, 'big')
        content = sol_bytes.rstrip(b'\0')
        try:
            text = content.decode('ascii')
            flag = f"0xfun{{{text}}}"
            print(f"\nFLAG: {flag}")
        except:
            print(f"Raw bytes: {content}")
            print(f"Hex: {content.hex()}")
    else:
        print("VERIFICATION FAILED!")
        mismatches = sum(1 for a, b in zip(check, real_outputs) if a != b)
        print(f"Mismatches: {mismatches}/{len(real_outputs)}")


if __name__ == '__main__':
    main()
