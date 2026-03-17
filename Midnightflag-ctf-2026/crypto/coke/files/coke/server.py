import hashlib
import json
import os
import secrets
import socketserver
from typing import Any, Dict, List, Tuple

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

Q = 2
M = 64
N_SECRET = 32
K = 16
LAMBDA = 16
DIST_RANK = 2
T = (N_SECRET - K) // 2

N = N_SECRET + LAMBDA

MOD_POLY = (1 << 64) | (1 << 61) | (1 << 34) | (1 << 9) | 1
MASK64 = (1 << 64) - 1


def gf_reduce(a: int) -> int:
    while a.bit_length() > 64:
        shift = a.bit_length() - 65
        a ^= MOD_POLY << shift
    return a & MASK64


def gf_mul(a: int, b: int) -> int:
    res = 0
    aa = a
    bb = b
    while bb:
        if bb & 1:
            res ^= aa
        bb >>= 1
        aa <<= 1
    return gf_reduce(res)


def gf_square(a: int) -> int:
    return gf_mul(a, a)


def gf_frob(a: int, pow_: int = 1) -> int:
    for _ in range(pow_):
        a = gf_square(a)
    return a


def gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError
    u, v = a, MOD_POLY
    g1, g2 = 1, 0
    while u != 1:
        j = (u.bit_length() - 1) - (v.bit_length() - 1)
        if j < 0:
            u, v = v, u
            g1, g2 = g2, g1
            j = -j
        u ^= v << j
        g1 ^= g2 << j
    return gf_reduce(g1)


def mat_mul(A: List[List[int]], B: List[List[int]]) -> List[List[int]]:
    r = len(A)
    m = len(A[0])
    assert m == len(B)
    c = len(B[0])
    cols = [[B[i][j] for i in range(m)] for j in range(c)]
    out = []
    for i in range(r):
        row_out = []
        for j in range(c):
            acc = 0
            col = cols[j]
            for k in range(m):
                aik = A[i][k]
                if aik:
                    acc ^= gf_mul(aik, col[k])
            row_out.append(acc)
        out.append(row_out)
    return out


def mat_rank(A: List[List[int]]) -> int:
    if not A:
        return 0
    M = [row[:] for row in A]
    nrows = len(M)
    ncols = len(M[0])
    r = 0
    for c in range(ncols):
        piv = None
        for i in range(r, nrows):
            if M[i][c] != 0:
                piv = i
                break
        if piv is None:
            continue
        if piv != r:
            M[r], M[piv] = M[piv], M[r]
        invp = gf_inv(M[r][c])
        if M[r][c] != 1:
            for j in range(c, ncols):
                M[r][j] = gf_mul(M[r][j], invp)
        for i in range(r + 1, nrows):
            factor = M[i][c]
            if factor:
                for j in range(c, ncols):
                    M[i][j] ^= gf_mul(factor, M[r][j])
        r += 1
        if r == nrows:
            break
    return r


def rank_q_elems(elems: List[int]) -> int:
    piv = {}
    for v in elems:
        x = v & MASK64
        while x:
            col = x.bit_length() - 1
            if col in piv:
                x ^= piv[col]
            else:
                piv[col] = x
                break
    return len(piv)


def random_independent_elems(count: int) -> List[int]:
    elems = []
    while len(elems) < count:
        x = secrets.randbits(M)
        if x == 0:
            continue
        if rank_q_elems(elems + [x]) == len(elems) + 1:
            elems.append(x)
    return elems


def moore_matrix(g: List[int], k: int) -> List[List[int]]:
    rows = []
    cur = g[:]
    rows.append(cur)
    for _ in range(1, k):
        cur = [gf_square(x) for x in cur]
        rows.append(cur)
    return rows


def mat_concat_h(A: List[List[int]], B: List[List[int]]) -> List[List[int]]:
    return [ra + rb for ra, rb in zip(A, B)]


def gf2_rank(rows: List[int], n: int) -> int:
    piv = {}
    for r in rows:
        x = r & ((1 << n) - 1)
        while x:
            col = x.bit_length() - 1
            if col in piv:
                x ^= piv[col]
            else:
                piv[col] = x
                break
    return len(piv)


def random_invertible_bin_matrix(n: int) -> List[int]:
    while True:
        rows = [secrets.randbits(n) for _ in range(n)]
        if gf2_rank(rows, n) == n:
            return rows


def field_row_mul_binmat(row: List[int], bin_rows: List[int], n: int) -> List[int]:
    out = [0] * n
    for i, vi in enumerate(row):
        if vi == 0:
            continue
        bits = bin_rows[i]
        x = bits
        while x:
            lsb = x & -x
            j = lsb.bit_length() - 1
            out[j] ^= vi
            x ^= lsb
    return out


def field_mat_mul_binmat(
    M: List[List[int]], bin_rows: List[int], n: int
) -> List[List[int]]:
    return [field_row_mul_binmat(row, bin_rows, n) for row in M]


def serialize_field_vec(vec: List[int]) -> bytes:
    return b"".join(int.to_bytes(x, 8, "little") for x in vec)


def gen_error_vector(N: int, t: int) -> List[int]:
    beta = random_independent_elems(t)
    while True:
        cols = [secrets.randbits(t) for _ in range(N)]
        if gf2_rank(cols, t) == t:
            break
    e = []
    for j in range(N):
        col = cols[j]
        val = 0
        for i in range(t):
            if (col >> i) & 1:
                val ^= beta[i]
        e.append(val)
    return e


def keygen() -> Dict[str, Any]:
    g = random_independent_elems(N_SECRET)
    Gsec = moore_matrix(g, K)

    while True:
        A = [[secrets.randbits(M) for _ in range(DIST_RANK)] for __ in range(K)]
        if mat_rank(A) == DIST_RANK:
            break
    while True:
        B = [[secrets.randbits(M) for _ in range(LAMBDA)] for __ in range(DIST_RANK)]
        if mat_rank(B) == DIST_RANK:
            break
    X = mat_mul(A, B)

    P_rows = random_invertible_bin_matrix(N)

    G0 = mat_concat_h(X, Gsec)
    Gpub = field_mat_mul_binmat(G0, P_rows, N)
    return {
        "params": {
            "q": Q,
            "m": M,
            "n": N_SECRET,
            "k": K,
            "lam": LAMBDA,
            "s": DIST_RANK,
            "t": T,
            "field_poly": {"degree": 64, "exponents": [64, 61, 34, 9, 0]},
        },
        "Gpub": Gpub,
    }


def encrypt(Gpub: List[List[int]], flag: bytes) -> Dict[str, Any]:
    msg = [secrets.randbits(M) for _ in range(K)]
    key = hashlib.sha256(serialize_field_vec(msg)).digest()

    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(flag)

    codeword = [0] * N
    for i in range(K):
        mi = msg[i]
        if mi == 0:
            continue
        row = Gpub[i]
        for j in range(N):
            rij = row[j]
            if rij:
                codeword[j] ^= gf_mul(mi, rij)

    e = gen_error_vector(N, T)
    y = [codeword[j] ^ e[j] for j in range(N)]

    return {
        "aes": {"nonce": nonce.hex(), "ct": ct.hex(), "tag": tag.hex()},
        "y": [f"{x:016x}" for x in y],
    }


def build_challenge() -> Dict[str, Any]:
    try:
        with open("flag.txt", "rb") as f:
            flag = f.read().strip()
    except FileNotFoundError:
        flag = b"MCTF{flag_de_baase}"
    inst = keygen()
    enc = encrypt(inst["Gpub"], flag)
    Gpub_hex = [[f"{x:016x}" for x in row] for row in inst["Gpub"]]
    return {
        "params": inst["params"],
        "Gpub": Gpub_hex,
        "cipher": enc,
        "note": "Classic Overbeck is bait. Distortion rank is low on purpose. Have fun.",
    }


CHALL = build_challenge()


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        blob = json.dumps(CHALL, separators=(",", ":")).encode() + b"\n"
        self.wfile.write(blob)


def main():
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "1337"))
    with socketserver.ThreadingTCPServer((host, port), Handler) as srv:
        srv.allow_reuse_address = True
        srv.serve_forever()


if __name__ == "__main__":
    main()
