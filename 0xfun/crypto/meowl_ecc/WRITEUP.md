# MeOwl ECC — Crypto (50pts, Beginner)

> "Smart's attack is broken on my curve, so I'm safe."

## Summary

ECDLP on an **anomalous** elliptic curve (#E(Fp) = p) over Fp. The challenge uses a trick: **non-canonical** lifts to the p-adic curve, which makes the standard Smart's attack implementation fail. The solution requires using random lifts with `randint(0, p-1)*p` in the p-adic curve construction.

**Flag:** `0xfun{n0n_c4n0n1c4l_l1f7s_r_c00l}`

## Challenge Analysis

### Parameters

```python
p = 1070960903638793793346073212977144745230649115077006408609822474051879875814028659881855169
a = 0
b = 19
E: y^2 = x^3 + 19  (mod p)

P = (Px, Py)  # base point
Q = (Qx, Qy)  # Q = d*P, we want to recover d

# Encryption: DES(AES(flag)) with keys derived from d
```

### Anomaly verification

```sage
sage: E = EllipticCurve(GF(p), [0, 19])
sage: E.order() == p
True
```

The curve is **anomalous**: #E(Fp) = p. This makes it vulnerable to Smart's attack.

## Smart's Attack

### Theoretical foundation

For anomalous curves, the ECDLP can be solved in polynomial time using the **formal group logarithm** in Qp:

1. Lift P and Q from E(Fp) to E(Qp) (p-adics)
2. Multiply by p: pP_Qp, pQ_Qp
3. Apply the map phi: phi(x,y) = -x/y
4. Compute d = phi(pQ) / phi(pP) mod p

### The challenge trick: non-canonical lifts

The **standard** Smart's attack implementation uses:

```sage
Eqp = EllipticCurve(Qp(p, 2), [ZZ(t) for t in E.a_invariants()])
```

This creates a **canonical** lift. The challenge says "Smart's attack is broken" because this canonical lift does NOT work here.

The correct solution uses **random lifts**:

```sage
Eqp = EllipticCurve(Qp(p, 2), [ZZ(t) + randint(0, p-1)*p for t in E.a_invariants()])
```

The `randint(0, p-1)*p` term adds a multiple of p to the curve coefficients, creating a non-canonical lift that DOES work.

## Exploit

```sage
#!/usr/bin/env sage
import hashlib
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes

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

E = EllipticCurve(GF(p), [a, b])
P = E(Px, Py)
Q = E(Qx, Qy)

def SmartAttack(P, Q, p):
    E = P.curve()
    # KEY: use randint(0, p-1)*p for non-canonical lift
    Eqp = EllipticCurve(Qp(p, 2), [ZZ(t) + randint(0, p-1)*p for t in E.a_invariants()])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P, y_P = p_times_P.xy()
    x_Q, y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)

d = SmartAttack(P, Q, p)
assert d * P == Q

# Decrypt
k = long_to_bytes(int(d))
aes_key = hashlib.sha256(k + b"MeOwl::AES").digest()[:16]
des_key = hashlib.sha256(k + b"MeOwl::DES").digest()[:8]

c1 = DES.new(des_key, DES.MODE_CBC, iv=des_iv).decrypt(ciphertext)
c1 = unpad(c1, 8)
flag = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv).decrypt(c1)
flag = unpad(flag, 16)

print(f"FLAG: {flag.decode()}")
```

### Execution with Docker + SageMath

```dockerfile
FROM sagemath/sagemath:latest
RUN sage -pip install pycryptodome
WORKDIR /app
COPY . /app
CMD ["sage", "solve.sage"]
```

```bash
$ docker build -t meowl-solver .
$ docker run --rm meowl-solver
d = 797362141196384868007066615792142575269512834174354422840008233995912822094171106431346799
Check: True
FLAG: 0xfun{n0n_c4n0n1c4l_l1f7s_r_c00l}
```

## Lessons Learned

1. **Anomalous curves are weak**: if #E(Fp) = p, Smart's attack solves the ECDLP in polynomial time.

2. **Non-canonical lifts**: the hint "Smart's attack is broken" was literal - the canonical lift fails. The solution requires adding `randint(0, p-1)*p` to the p-adic curve coefficients.

3. **p-adic debugging**: when `p*P_Qp.xy()` gives a `ZeroDivisionError`, the problem is usually in the precision or an incorrect lift, not in the fundamental algorithm.

4. **SageMath is indispensable for ECC**: implementing correct p-adic arithmetic in pure Python is extremely difficult. Docker with `sagemath/sagemath:latest` is the practical solution for CTFs.

## References

- Smart's Attack: "The Discrete Logarithm Problem on Elliptic Curves of Trace One" - Nigel Smart (1999)
- [Crypto-Cat CTF Tools](https://github.com/jvdsn/crypto-attacks) - reference implementation
