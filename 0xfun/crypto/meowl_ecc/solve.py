#!/usr/bin/env python3
"""MeOwl ECC - Smart's attack implementation in pure Python
For anomalous curves where #E(Fp) = p"""
import hashlib
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes

# Challenge parameters
p = 1070960903638793793346073212977144745230649115077006408609822474051879875814028659881855169
a = 0
b = 19

Px = 850194424131363838588909772639181716366575918001556629491986206564277588835368712774900915
Py = 749509706400667976882772182663506383952119723848300900481860146956631278026417920626334886

Qx = 54250358642669756154015134950152636682437522715786363311759940981383592083045988845753867
Qy = 324772290891069325219931358863917293864610371020855881775477694333357303867104131696431188

aes_iv = bytes.fromhex("7d0e47bb8d111b626f0e17be5a761a14")
des_iv = bytes.fromhex("86fd0c44751700d4")
ciphertext = bytes.fromhex(
    "7d34910bca6f505e638ed22f412dbf1b50d03243b739de0090d07fb097ec0a2c"
    "a19158949f32e39cd84adea33d2229556f635237088316d2"
)

# --- Elliptic curve operations over Fp ---

def modinv(a, m):
    """Modular inverse using extended GCD"""
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = egcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    gcd, x, _ = egcd(a % m, m)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % m + m) % m

def ec_add(P1, P2, a, p):
    """Elliptic curve point addition y^2 = x^3 + ax + b mod p"""
    if P1 is None:
        return P2
    if P2 is None:
        return P1

    x1, y1 = P1
    x2, y2 = P2

    if x1 == x2:
        if y1 == y2:
            # Point doubling
            s = (3 * x1 * x1 + a) * modinv(2 * y1, p) % p
        else:
            # P + (-P) = O
            return None
    else:
        # Point addition
        s = (y2 - y1) * modinv(x2 - x1, p) % p

    x3 = (s * s - x1 - x2) % p
    y3 = (s * (x1 - x3) - y1) % p
    return (x3, y3)

def ec_mul(k, P, a, p):
    """Scalar multiplication k*P using double-and-add"""
    if k == 0:
        return None
    if k == 1:
        return P

    result = None
    addend = P

    while k:
        if k & 1:
            result = ec_add(result, addend, a, p)
        addend = ec_add(addend, addend, a, p)
        k >>= 1

    return result

def ec_order_bruteforce(P, a, p, max_tries=10000):
    """Estimate point order (for verification)"""
    Q = P
    for i in range(1, max_tries):
        if Q is None:
            return i
        Q = ec_add(Q, P, a, p)
    return None

# --- Smart's attack using p-adic approximation ---

def smart_attack_padic_approximation(P, Q, a, p, precision=50):
    """
    Smart's attack implementation using approximate p-adic arithmetic.
    For anomalous curves (#E(Fp) = p), we lift the points to Qp
    and compute the discrete logarithm using the phi map.
    """
    print(f"Implementing Smart's attack with p-adic precision = {precision}")

    # Lift P to Qp (precision p^2 sufficient)
    # We look for (x, y) such that y^2 = x^3 + ax + b (mod p^2)
    # Using Hensel lifting

    def lift_point_hensel(x0, y0, a, b, p, prec):
        """Hensel lifting of a point from Fp to Zp with precision prec"""
        x = x0
        y = y0
        pk = p

        for k in range(1, prec):
            # y^2 - (x^3 + ax + b) = 0 (mod p^k)
            # We want to adjust y += t*p^(k-1) to make it zero mod p^k
            f_val = (y * y - (x**3 + a*x + b)) % (p ** (k + 1))

            if f_val % (p ** k) == 0:
                continue  # already zero mod p^k

            # df/dy = 2y
            df = (2 * y) % p
            if df == 0:
                print(f"WARNING: derivative zero at lift step {k}")
                break

            t = (-f_val // (p ** k)) * modinv(df, p) % p
            y = (y + t * (p ** k)) % (p ** (k + 1))

        return x, y

    # Verify that P and Q are on the curve
    assert (Py**2 - (Px**3 + a*Px + b)) % p == 0, "P not on curve"
    assert (Qy**2 - (Qx**3 + a*Qx + b)) % p == 0, "Q not on curve"

    # Lift P and Q
    print("Lifting points to Qp...")
    P_lifted = lift_point_hensel(Px, Py, a, b, p, precision)
    Q_lifted = lift_point_hensel(Qx, Qy, a, b, p, precision)

    xP, yP = P_lifted
    xQ, yQ = Q_lifted

    # Compute p*P and p*Q in Qp (mod p^precision)
    # For sufficient precision, we use the multiplication formula
    pmod = p ** precision

    # p*P in Qp (using iterated doubling formula log2(p) times)
    # Simplification: p*P ~ (xP, yP + p*correction)
    # But it's more direct to use the phi projection

    # phi: E(Qp)[p] -> Qp/Zp
    # phi(x, y) = -x/y (in the formal group)

    # Compute phi(p*P) and phi(p*Q)
    # We need p*P mod p^precision

    # Using scalar multiplication in Qp
    def ec_mul_padic(k, Px, Py, a, pmod):
        """Scalar multiplication in Qp with modulus pmod"""
        if k == 0:
            return None, None

        result_x, result_y = None, None
        addend_x, addend_y = Px, Py

        while k > 0:
            if k & 1:
                if result_x is None:
                    result_x, result_y = addend_x, addend_y
                else:
                    result_x, result_y = ec_add_padic(result_x, result_y, addend_x, addend_y, a, pmod)

            if k > 1:
                addend_x, addend_y = ec_add_padic(addend_x, addend_y, addend_x, addend_y, a, pmod)
            k >>= 1

        return result_x, result_y

    def ec_add_padic(x1, y1, x2, y2, a, pmod):
        """Point addition in Qp mod pmod"""
        if x1 == x2:
            if y1 == y2:
                # Doubling
                s = (3 * x1 * x1 + a) * modinv(2 * y1, pmod) % pmod
            else:
                return None, None
        else:
            s = (y2 - y1) * modinv((x2 - x1) % pmod, pmod) % pmod

        x3 = (s * s - x1 - x2) % pmod
        y3 = (s * (x1 - x3) - y1) % pmod
        return x3, y3

    print("Computing p*P and p*Q...")
    pP_x, pP_y = ec_mul_padic(p, xP, yP, a, pmod)
    pQ_x, pQ_y = ec_mul_padic(p, xQ, yQ, a, pmod)

    if pP_x is None or pQ_x is None:
        raise ValueError("p*P or p*Q is point at infinity")

    # phi(p*P) = -x/(y) in the formal group
    phi_pP = (-pP_x * modinv(pP_y, pmod)) % pmod
    phi_pQ = (-pQ_x * modinv(pQ_y, pmod)) % pmod

    print(f"phi(p*P) = {phi_pP}")
    print(f"phi(p*Q) = {phi_pQ}")

    # d = phi(p*Q) / phi(p*P) mod p
    d = (phi_pQ * modinv(phi_pP, p)) % p

    return d

# --- Main ---

print("=" * 60)
print("MeOwl ECC - Smart's Attack")
print("=" * 60)

P = (Px, Py)
Q = (Qx, Qy)

# Verify anomalous curve
print(f"\np = {p}")
print(f"Checking if the curve is anomalous...")

# To verify that #E(Fp) = p, we can compute p*P
print("Computing p*P...")
pP = ec_mul(p, P, a, p)
if pP is None:
    print("p*P = O (point at infinity)")
    print("Curve confirmed as anomalous: #E(Fp) = p")
else:
    print(f"ERROR: p*P != O, the curve is NOT anomalous")
    print(f"p*P = {pP}")

print("\n" + "=" * 60)
print("Applying Smart's attack...")
print("=" * 60)

try:
    d = smart_attack_padic_approximation(P, Q, a, p, precision=3)

    print(f"\nRecovered private key: d = {d}")

    # Verify
    print("\nVerifying d*P == Q...")
    Q_check = ec_mul(d, P, a, p)
    if Q_check == Q:
        print("Verification successful: d*P == Q")
    else:
        print("Verification FAILED")
        print(f"d*P = {Q_check}")
        print(f"Q   = {Q}")
        exit(1)

    # Decrypt flag
    print("\n" + "=" * 60)
    print("Decrypting flag...")
    print("=" * 60)

    k = long_to_bytes(int(d))
    aes_key = hashlib.sha256(k + b"MeOwl::AES").digest()[:16]
    des_key = hashlib.sha256(k + b"MeOwl::DES").digest()[:8]

    # DES decrypt -> AES decrypt
    c1 = DES.new(des_key, DES.MODE_CBC, iv=des_iv).decrypt(ciphertext)
    c1 = unpad(c1, 8)
    flag_bytes = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv).decrypt(c1)
    flag = unpad(flag_bytes, 16).decode()

    print(f"\nFLAG: {flag}")

except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()
