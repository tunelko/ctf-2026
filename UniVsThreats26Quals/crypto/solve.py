#!/usr/bin/env python3
"""
Solver for UniVsThreats26 Quals - Crypto: Deep-Space Transmission
"""
import hashlib
import os
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from fpylll import IntegerMatrix, LLL

# Bruteforce epoch time from hash ========
def find_epoch_time(target_hash):
    for h in range(24):
        for m in range(60):
            for s in range(60):
                time_str = f"{h:02d}:{m:02d}:{s:02d}"
                hsh = hashlib.sha256(time_str.encode()).hexdigest()[:16]
                if hsh == target_hash:
                    return h, m, s
    raise ValueError("Epoch time not found")

# Derive LCG params from Halley's comet ========
def derive_ab(year, month, day, hour, minute, second):
    from skyfield.api import load
    from skyfield.data import mpc
    from skyfield.constants import GM_SUN_Pitjeva_2005_km3_s2 as GM_SUN

    if not os.path.exists('CometEls.txt'):
        import urllib.request
        urllib.request.urlretrieve(
            "https://minorplanetcenter.net/iau/Ephemerides/Comets/Soft00Cmt.txt",
            'CometEls.txt')

    with load.open('CometEls.txt') as f:
        comets = mpc.load_comets_dataframe(f)
    comets = comets.set_index('designation', drop=False)
    row = comets.loc['1P/Halley']

    ts = load.timescale()
    t = ts.utc(year, month, day, hour, minute, second)
    eph = load('de421.bsp')
    sun = eph['sun']
    halley = sun + mpc.comet_orbit(row, ts, GM_SUN)

    astrometric = sun.at(t).observe(halley)
    x, y, z = astrometric.position.au
    coord_string = f"{x:.10f}_{y:.10f}_{z:.10f}"

    h_a = hashlib.sha512((coord_string + "_A").encode()).digest()
    h_b = hashlib.sha512((coord_string + "_B").encode()).digest()
    return bytes_to_long(h_a), bytes_to_long(h_b)

# Solve truncated LCG via lattice CVP ========
def solve_truncated_lcg(a, b, p, steps, t_vals, unknown_bits):
    U = unknown_bits
    two_U = 1 << U
    a_inv_m1 = pow(a - 1, -1, p)

    def compose_lcg(n):
        A_n = pow(a, n, p)
        B_n = (b * (A_n - 1) * a_inv_m1) % p
        return A_n, B_n

    # Build linear relations: A_i * e_0 - e_i ≡ c_i (mod p)
    n = len(steps) - 1
    coeffs, constants = [], []
    for i in range(1, n + 1):
        A_i, B_i = compose_lcg(steps[i])
        c_i = (t_vals[i] * two_U - A_i * t_vals[0] * two_U - B_i) % p
        coeffs.append(A_i)
        constants.append(c_i)

    # Kannan CVP embedding (dim = n+2)
    dim = n + 2
    M = IntegerMatrix(dim, dim)
    for i in range(n):
        M[i, i] = p
    for i in range(n):
        M[n, i] = coeffs[i]
    M[n, n] = 1
    for i in range(n):
        M[n + 1, i] = constants[i]
    M[n + 1, n + 1] = 1

    LLL.reduction(M)

    # Find solution row (last element = ±1)
    for i in range(dim):
        row = [M[i, j] for j in range(dim)]
        if abs(row[n + 1]) == 1:
            sign = row[n + 1]
            e_0 = -sign * row[n]
            if 0 <= e_0 < two_U:
                s_0 = (t_vals[0] * two_U + e_0) % p
                # Verify
                ok = all(
                    ((compose_lcg(steps[j])[0] * s_0 + compose_lcg(steps[j])[1]) % p) >> U == t_vals[j]
                    for j in range(len(steps))
                )
                if ok:
                    return s_0, compose_lcg
    raise ValueError("Lattice solution not found")


def main():
    # Parse output
    epoch_hash = "8b156702c993b9b5"
    p = 10035410270612815279389330410121900529620495869479898461384631211745452304638984576440553552006414411373806160282016417372459090604747980402493134112626213
    t_vals = [
        1129223615711367884405014640005288172041367198689786688285,
        579514026315281536883405991880758556036404753274817543322,
        1279648546218423539959079224022586160480305721841176089544,
        1946366015289015629063708515503091199628321083313573104031,
        3902208990133988884490762855871313599751888895643028675415,
    ]
    iv = bytes.fromhex("ba04a327ffd0c69205ff5dcb5f463d9c")
    ct = bytes.fromhex("1879e4d0f174c9a6d2be99b6f632cc0f3ea89989e69dbd080761cb616b37d8eba37635de6c6475d741f69450c8259590")

    STEPS = [0, 4, 10, 18, 28]
    UNKNOWN_BITS = 320

    # Step 1
    print("[*] Bruteforcing epoch time...")
    hour, minute, second = find_epoch_time(epoch_hash)
    print(f"[+] Epoch time: {hour:02d}:{minute:02d}:{second:02d}")

    # Step 2
    print("[*] Deriving LCG parameters from Halley's comet position...")
    a, b = derive_ab(2026, 1, 26, hour, minute, second)
    print(f"[+] a = {a}")
    print(f"[+] b = {b}")

    # Step 3
    print("[*] Solving truncated LCG via lattice reduction...")
    s_0, compose = solve_truncated_lcg(a, b, p, STEPS, t_vals, UNKNOWN_BITS)
    print(f"[+] Recovered s_0 = {s_0}")
# Compute final state (one step after last STEP=28 → step 29)
    A_29, B_29 = compose(29)
    final_state = (A_29 * s_0 + B_29) % p

    aes_key = hashlib.sha256(long_to_bytes(final_state)).digest()
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    flag = unpad(cipher.decrypt(ct), AES.block_size)
    print(f"[+] FLAG: {flag.decode()}")


if __name__ == "__main__":
    main()
