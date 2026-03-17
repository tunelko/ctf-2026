#!/usr/bin/env python3
"""
Retargeted solver — Ratchet leaks linear relation between mask vectors.

After 3 queries, the 4th mask u_4 is a deterministic linear combo of u_1,u_2,u_3.
Since z_i = u_i + c_i * taylor(f, x_i), and shift_taylor(taylor(f,xi), xj-xi) = taylor(f,xj),
all the taylor(f) terms collapse:

  R = z_4 - shift(z_3, x4-x3) - mu*shift(z_2, x4-x2) - nu*shift(z_1, x4-x1)
    = (c_4 - c_3 - mu*c_2 - nu*c_1) * taylor(f, x4)

If alpha = c_4 - c_3 - mu*c_2 - nu*c_1 != 0, we recover all Taylor coefficients
of f at x4, hence the full polynomial f, hence f(admin_x).
"""

from pwn import *
import hashlib
import os

# ---- Server constants ----
P = 65993754221047993367757014757310801859001451513902355017284390150045199658079
Q = 32996877110523996683878507378655400929500725756951177508642195075022599829039
N = 32

def i2b(x):
    return x.to_bytes(32, "big")

def htag(tag, *parts):
    h = hashlib.sha256()
    h.update(tag)
    for part in parts:
        if isinstance(part, int):
            h.update(i2b(part))
        elif isinstance(part, bytes):
            h.update(len(part).to_bytes(2, "big"))
            h.update(part)
        elif isinstance(part, (list, tuple)):
            h.update(len(part).to_bytes(2, "big"))
            for x in part:
                h.update(i2b(x % Q))
    return int.from_bytes(h.digest(), "big") % Q

def proof_chal(C, x, Y, A, B):
    return htag(b"chal", C, x, Y, A, B)

def ratchet_mu(x, Y, A, B):
    mu = htag(b"ratchet", x, Y, A, B)
    return mu if mu != 0 else 1

def ratchet_nu(x, Y, A, B, s, t):
    nu = htag(b"tail", x, Y, A, B, s, t)
    return nu if nu != 0 else 1

def jet_delta(x, Y, A, B, s, t):
    return htag(b"jet", x, Y, A, B, s, t)

# ---- Polynomial / Taylor operations ----
BINOM = [[0]*N for _ in range(N)]
for i in range(N):
    BINOM[i][0] = 1
    BINOM[i][i] = 1
for i in range(2, N):
    for j in range(1, i):
        BINOM[i][j] = (BINOM[i-1][j-1] + BINOM[i-1][j]) % Q

def vadd(a, b): return [(x+y) % Q for x,y in zip(a,b)]
def vsub(a, b): return [(x-y) % Q for x,y in zip(a,b)]
def vscale(k, a): return [(k*x) % Q for x in a]

def shift_taylor(a, delta):
    out = [0]*N
    pw = [1]*N
    for i in range(1, N): pw[i] = pw[i-1] * delta % Q
    for k in range(N):
        acc = 0
        for j in range(k, N):
            acc += BINOM[j][k] * pw[j-k] * a[j]
        out[k] = acc % Q
    return out

def taylor_to_coeff(a, x): return shift_taylor(a, (-x) % Q)
def coeff_to_taylor(a, x): return shift_taylor(a, x)

def poly_eval(coeffs, x):
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % Q
    return acc

def modinv(a, m=Q): return pow(a, m-2, m)

# ---- Connect ----
HOST = os.environ.get('HOST', 'dyn-03.midnightflag.fr')
PORT = int(os.environ.get('PORT', '12159'))
r = remote(HOST, PORT)

# Parse header
r.recvuntil(b'C = ')
C = int(r.recvline().strip(), 16)
r.recvuntil(b'admin_x = ')
admin_x = int(r.recvline().strip(), 16)
print(f"[*] C = {hex(C)[:20]}...")
print(f"[*] admin_x = {hex(admin_x)[:20]}...")

def do_query(x_val):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b'x = ', hex(x_val).encode())
    r.recvuntil(b'Y = '); Y = int(r.recvline().strip(), 16)
    r.recvuntil(b'A = '); A = int(r.recvline().strip(), 16)
    r.recvuntil(b'B = '); B = int(r.recvline().strip(), 16)
    r.recvuntil(b's = '); s = int(r.recvline().strip(), 16)
    r.recvuntil(b't = '); t = int(r.recvline().strip(), 16)
    r.recvuntil(b'w = ')
    w_raw = r.recvline().strip().decode().split()
    w = [int(x, 16) for x in w_raw]
    return {'x': x_val, 'Y': Y, 'A': A, 'B': B, 's': s, 't': t, 'w': w}

# Make 4 queries at distinct points (not admin_x)
# Choose simple values that won't collide with admin_x
queries = []
for i in range(4):
    x_val = (i + 1) % Q
    if x_val == admin_x:
        x_val = (x_val + 100) % Q
    print(f"[*] Query {i+1}: x = {x_val}")
    q = do_query(x_val)
    queries.append(q)
    print(f"  Y = {hex(q['Y'])[:20]}... s = {hex(q['s'])[:20]}...")

# Recover z_i from w_i: z_i = shift_taylor(w_i, -delta_i)
zs = []
for q in queries:
    delta = jet_delta(q['x'], q['Y'], q['A'], q['B'], q['s'], q['t'])
    z = shift_taylor(q['w'], (-delta) % Q)
    zs.append(z)

# Compute challenge values c_i
cs = []
for q in queries:
    c = proof_chal(C, q['x'], q['Y'], q['A'], q['B'])
    cs.append(c)

# Compute mu and nu from public outputs
# mu = ratchet_mu(x2, Y2, A2, B2)  (from query 2 = queries[1])
# nu = ratchet_nu(x1, Y1, A1, B1, s1, t1)  (from query 1 = queries[0])
q1, q2, q3, q4 = queries
mu = ratchet_mu(q2['x'], q2['Y'], q2['A'], q2['B'])
nu = ratchet_nu(q1['x'], q1['Y'], q1['A'], q1['B'], q1['s'], q1['t'])

print(f"\n[*] mu = {hex(mu)[:20]}...")
print(f"[*] nu = {hex(nu)[:20]}...")

# Compute R = z4 - shift(z3, x4-x3) - mu*shift(z2, x4-x2) - nu*shift(z1, x4-x1)
x4 = q4['x']
shifted_z3 = shift_taylor(zs[2], (x4 - q3['x']) % Q)
shifted_z2 = shift_taylor(zs[1], (x4 - q2['x']) % Q)
shifted_z1 = shift_taylor(zs[0], (x4 - q1['x']) % Q)

R = vsub(zs[3], vadd(shifted_z3, vadd(vscale(mu, shifted_z2), vscale(nu, shifted_z1))))

# alpha = c4 - c3 - mu*c2 - nu*c1
alpha = (cs[3] - cs[2] - mu * cs[1] - nu * cs[0]) % Q
print(f"[*] alpha = {hex(alpha)[:20]}...")

if alpha == 0:
    print("[-] alpha = 0! Bad luck, retry with different query points")
    r.close()
    exit(1)

# T4 = R / alpha (component-wise)
alpha_inv = modinv(alpha)
T4 = vscale(alpha_inv, R)

print(f"[*] Taylor(f, x4)[0] = {hex(T4[0])[:20]}...")
print(f"[*] Taylor(f, x4)[1] = {hex(T4[1])[:20]}...")

# Recover f coefficients: f = taylor_to_coeff(T4, x4)
f_coeffs = taylor_to_coeff(T4, x4)

# Compute f(admin_x)
f_admin = poly_eval(f_coeffs, admin_x)
print(f"\n[*] f(admin_x) = {hex(f_admin)[:20]}...")

# Submit
r.sendlineafter(b'> ', b'2')
r.sendlineafter(b'f(admin_x) = ', hex(f_admin).encode())
result = r.recvline().decode().strip()
print(f"\n[+] Result: {result}")

r.close()
