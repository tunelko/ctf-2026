#!/usr/bin/env python3
"""
Challenge: plane-or-exchange
Category:  crypto (knot theory DH)
Platform:  diceCTF 2026

The protocol is a Diffie-Hellman key exchange using knot invariants (Alexander polynomial).
The Alexander polynomial is multiplicative under connected sum (#), so:
  Alex(alice_pub) = Alex(public_info) * Alex(alice_priv)
  Alex(bob_pub)   = Alex(public_info) * Alex(bob_priv)
  shared          = normalize(Alex(alice_priv) * Alex(bob_pub))
                  = normalize(Alex(alice_pub) * Alex(bob_pub) / Alex(public_info))

We recover the shared polynomial without knowing private keys.

The invariant is computed exactly via:
1. Bareiss integer determinant at ~230 evaluation points (u = 2..231)
2. Newton divided-difference interpolation to recover the polynomial
"""
import hashlib
import sympy as sp
from fractions import Fraction

t = sp.Symbol('t', real=True, positive=True)

# === Challenge data ===
alice_pub = ([8, 15, 7, 26, 1, 4, 2, 12, 9, 18, 23, 25, 24, 14, 13, 16, 0, 3, 11, 10, 5, 20, 6, 21, 19, 17, 22],
             [5, 2, 23, 3, 25, 9, 26, 8, 24, 7, 14, 18, 12, 4, 20, 21, 6, 1, 19, 22, 10, 0, 16, 17, 15, 11, 13])
bob_pub = ([26, 9, 21, 4, 28, 8, 20, 7, 27, 1, 13, 25, 22, 17, 6, 15, 24, 3, 12, 29, 11, 16, 10, 0, 18, 2, 14, 5, 19, 23],
           [5, 18, 28, 27, 25, 19, 23, 13, 21, 24, 16, 15, 8, 29, 14, 11, 26, 22, 9, 7, 10, 3, 2, 6, 0, 12, 17, 20, 1, 4])
public_info = ([11, 0, 2, 4, 8, 3, 1, 10, 7, 6, 9, 5],
               [1, 9, 8, 10, 11, 7, 4, 6, 5, 3, 2, 0])
ciphertext = "288cdf5ecf3eb860e2cb6790bff63baceaebb6ed511cd94dd0753bac59962ef0cd171231dc406ac3cdc2ff299d78390ff3"

# === From protocol.py ===
def sweep(ap):
    l = len(ap)
    current_row = [0] * l
    matrix = []
    for pair in ap:
        c1, c2 = sorted(pair)
        diff = pair[1] - pair[0]
        s = 1 if diff > 0 else (-1 if diff < 0 else 0)
        for c in range(c1, c2):
            current_row[c] += s
        matrix.append(list(current_row))
    return matrix

def mine(point):
    x, o = point
    return sweep([*zip(x, o)])

# === Exact integer Bareiss determinant ===
def integer_det(mat):
    n = len(mat)
    M = [row[:] for row in mat]
    sign = 1
    prev = 1
    for k in range(n - 1):
        if M[k][k] == 0:
            for i in range(k + 1, n):
                if M[i][k] != 0:
                    M[k], M[i] = M[i], M[k]
                    sign *= -1
                    break
            else:
                return 0
        for i in range(k + 1, n):
            for j in range(k + 1, n):
                M[i][j] = (M[k][k] * M[i][j] - M[i][k] * M[k][j]) // prev
            M[i][k] = 0
        prev = M[k][k]
    return sign * M[n-1][n-1]

def evaluate_alexander(point, u_val):
    """Evaluate Alexander polynomial at u=1/t using exact integer arithmetic."""
    m = mine(point)
    n = len(m)
    row_mins = [min(row) for row in m]
    shifted = [[val - row_mins[i] for val in row] for i, row in enumerate(m)]
    mat = [[u_val**s for s in row] for row in shifted]
    det_val = integer_det(mat)
    S = sum(row_mins)
    numerator = det_val * u_val**(S + n - 1)
    denominator = (u_val - 1)**(n - 1)
    return numerator // denominator

def normalize(calculation):
    poly = sp.expand(sp.simplify(calculation))
    all_exponents = [term.as_coeff_exponent(t)[1] for term in poly.as_ordered_terms()]
    min_exp = min(all_exponents)
    poly *= t**(-min_exp)
    poly = sp.expand(sp.simplify(poly))
    if poly.coeff(t, 0) < 0:
        poly *= -1
    return poly

def main():
    # Evaluate shared(u) = Alex(alice)(u) * Alex(bob)(u) / Alex(pub)(u) at integer points
    N = 230
    u_points = list(range(2, 2 + N))
    print(f"[*] Evaluating shared polynomial at {N} integer points...")
    shared_values = []
    for u_val in u_points:
        a = evaluate_alexander(alice_pub, u_val)
        b = evaluate_alexander(bob_pub, u_val)
        p = evaluate_alexander(public_info, u_val)
        shared_values.append(a * b // p)

    # Newton divided-difference interpolation
    print("[*] Interpolating polynomial via Newton divided differences...")
    dd = [Fraction(v) for v in shared_values]
    n = len(u_points)
    actual_degree = n - 1
    for j in range(1, n):
        all_zero = True
        for i in range(n - 1, j - 1, -1):
            dd[i] = (dd[i] - dd[i-1]) / (u_points[i] - u_points[i-j])
            if dd[i] != 0:
                all_zero = False
        if all_zero:
            actual_degree = j - 1
            break
    print(f"    Polynomial degree: {actual_degree}")

    # Build polynomial in u using Horner from Newton form
    u = sp.Symbol('u')
    coeffs = [dd[i] for i in range(actual_degree + 1)]
    poly_expr = sp.Rational(int(coeffs[actual_degree].numerator), int(coeffs[actual_degree].denominator))
    for k in range(actual_degree - 1, -1, -1):
        poly_expr = sp.expand(poly_expr * (u - u_points[k]) +
                              sp.Rational(int(coeffs[k].numerator), int(coeffs[k].denominator)))

    # Convert u -> 1/t and normalize
    poly_t = sp.expand(poly_expr.subs(u, 1/t))
    norm_poly = normalize(poly_t)
    print(f"[*] Normalized polynomial: {norm_poly}")

    # Derive shared secret and decrypt
    shared_secret = hashlib.sha256(str(norm_poly).encode()).hexdigest()
    ct = bytes.fromhex(ciphertext)
    key = bytes.fromhex(shared_secret)
    while len(key) < len(ct):
        key += hashlib.sha256(key).digest()
    flag = bytes(a ^ b for a, b in zip(ct, key))
    print(f"\n[+] Flag: {flag.decode()}")

if __name__ == "__main__":
    main()
