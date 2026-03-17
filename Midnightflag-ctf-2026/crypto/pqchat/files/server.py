from __future__ import annotations

import argparse
import hashlib
import json
import os
import socketserver
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Callable, Dict, Iterable, List, Sequence, Tuple

import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


BANNER = r"""
== PQChat ==
"""

MENU = r"""
[1] show public parameters
[2] get handshake transcript
[3] get encrypted flag
[4] submit recovered secret (optional)
[5] quit
> """

VERSION = "pqchat.reduction.chain.v7"

N: int = 512
Q: int = 12289
K: int = 21

ETA_S: int = 7
ETA_E: int = 2

MAIN_SLOTS: int = 160
AUX_BAND_SLOTS: tuple[int, int, int, int] = (80, 80, 96, 96)
MAX_SAMPLES: int = 48

LAYOUT_SEED: bytes = b"pqchat.layout.v7.reduction-chain"
MASK_H_SEED: bytes = b"pqchat.mask-h.v7.reduction-chain"
MASK_G_SEED: bytes = b"pqchat.mask-g.v7.reduction-chain"

INSTANCE_PATH: str = "instance.json"
FLAG_PATH: str = "flag.txt"

MAIN_VALUE_TABLE: tuple[int, ...] = (-5, -4, -3, -2, -1, 0, 0, 1, 2, 3, 4, 5)
AUX_VALUE_TABLES: tuple[tuple[int, ...], ...] = (
    (-6, -5, -3, -2, -1, 0, 1, 2, 3, 5, 6),
    (-6, -4, -3, -1, 0, 1, 3, 4, 6),
    (-7, -5, -3, -2, -1, 0, 1, 2, 3, 5, 7),
    (-6, -5, -4, -2, -1, 0, 1, 2, 4, 5, 6),
)
ERROR_VALUE_TABLE: tuple[int, ...] = (-2, -1, 0, 0, 1, 2)


@dataclass
class Instance:
    version: str
    n: int
    q: int
    k: int
    eta_s: int
    eta_e: int
    layout_seed_hex: str
    mask_h_seed_hex: str
    mask_g_seed_hex: str
    s_base: List[int]
    blind_bases: List[List[int]]
    nonce_hex: str
    ct_hex: str
    tag_hex: str


def modq(x: int, q: int) -> int:
    return int(x % q)


def poly_add(a: List[int], b: List[int], q: int) -> List[int]:
    if len(a) != len(b):
        raise ValueError("poly_add: length mismatch")
    return [int((x + y) % q) for x, y in zip(a, b)]


def poly_mul(a: List[int], b: List[int], q: int) -> List[int]:
    if len(a) != len(b):
        raise ValueError("poly_mul: length mismatch")
    n = len(a)
    aa = np.array(a, dtype=np.int64)
    bb = np.array(b, dtype=np.int64)
    c = np.convolve(aa, bb)
    res = c[:n].copy()
    res[: n - 1] -= c[n:]
    res %= q
    return [int(x) for x in res.tolist()]


def pack_poly14(p: List[int], q: int) -> bytes:
    acc = 0
    bits = 0
    out = bytearray()
    for c in p:
        v = int(c % q)
        acc |= v << bits
        bits += 14
        while bits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            bits -= 8
    if bits:
        out.append(acc & 0xFF)
    return bytes(out)


def unpack_poly14(buf: bytes, n: int, q: int) -> List[int]:
    acc = 0
    bits = 0
    out: List[int] = []
    idx = 0
    for _ in range(n):
        while bits < 14:
            if idx >= len(buf):
                raise ValueError("unpack_poly14: truncated buffer")
            acc |= buf[idx] << bits
            bits += 8
            idx += 1
        v = acc & ((1 << 14) - 1)
        acc >>= 14
        bits -= 14
        out.append(int(v % q))
    return out


def poly_to_bytes(p: List[int], q: int) -> bytes:
    out = bytearray()
    for c in p:
        out += int(c % q).to_bytes(2, "little")
    return bytes(out)


@lru_cache(maxsize=None)
def _prime_factors(m: int) -> tuple[int, ...]:
    if m <= 1:
        return ()

    n = m
    out: List[int] = []
    d = 2
    while d * d <= n:
        if n % d == 0:
            out.append(d)
            while n % d == 0:
                n //= d
        d += 1
    if n > 1:
        out.append(n)
    return tuple(out)


@lru_cache(maxsize=None)
def primitive_root(q: int) -> int:
    if q < 3:
        raise ValueError("primitive_root: q must be an odd prime")

    factors = _prime_factors(q - 1)
    for g in range(2, q):
        if all(pow(g, (q - 1) // p, q) != 1 for p in factors):
            return g
    raise ValueError("primitive_root: no generator found")


@lru_cache(maxsize=None)
def negacyclic_root(n: int, q: int) -> int:
    if (q - 1) % (2 * n) != 0:
        raise ValueError("negacyclic_root: 2n must divide q-1")

    g = primitive_root(q)
    zeta = pow(g, (q - 1) // (2 * n), q)
    if pow(zeta, n, q) != (q - 1) % q:
        raise ValueError("negacyclic_root: invalid 2n-th root")
    return zeta


@lru_cache(maxsize=None)
def negacyclic_roots(n: int, q: int) -> tuple[int, ...]:
    zeta = negacyclic_root(n, q)
    return tuple(pow(zeta, 2 * j + 1, q) for j in range(n))


@lru_cache(maxsize=None)
def negacyclic_eval_matrices(n: int, q: int) -> tuple[np.ndarray, np.ndarray, int]:
    roots = negacyclic_roots(n, q)
    forward = np.empty((n, n), dtype=np.int64)
    inverse = np.empty((n, n), dtype=np.int64)

    for row, r in enumerate(roots):
        inv_r = pow(r, q - 2, q)
        cur_f = 1
        cur_i = 1
        for col in range(n):
            forward[row, col] = cur_f
            inverse[col, row] = cur_i
            cur_f = (cur_f * r) % q
            cur_i = (cur_i * inv_r) % q

    return forward, inverse, pow(n, -1, q)


def spec_forward(poly: List[int], q: int) -> List[int]:
    n = len(poly)
    forward, _, _ = negacyclic_eval_matrices(n, q)
    vec = np.array([int(x % q) for x in poly], dtype=np.int64)
    out = (forward @ vec) % q
    return [int(x) for x in out.tolist()]


def spec_inverse(spec: List[int], q: int) -> List[int]:
    n = len(spec)
    _, inverse, inv_n = negacyclic_eval_matrices(n, q)
    vec = np.array([int(x % q) for x in spec], dtype=np.int64)
    out = (inverse @ vec) % q
    out = (out * inv_n) % q
    return [int(x) for x in out.tolist()]


def _shake_bytes(seed: bytes, out_len: int) -> bytes:
    return hashlib.shake_256(seed).digest(out_len)


def _rank_indices(seed: bytes, tag: bytes, n: int) -> List[int]:
    scored = []
    for i in range(n):
        digest = hashlib.sha256(seed + tag + i.to_bytes(4, "little")).digest()
        scored.append((digest, i))
    scored.sort()
    return [i for _, i in scored]


def _sample_from_table(seed: bytes, tag: bytes, table: Sequence[int], count: int, q: int) -> List[int]:
    raw = _shake_bytes(seed + tag, count)
    out: List[int] = []
    for b in raw:
        out.append(int(table[b % len(table)]) % q)
    return out


def _ensure_nonzero(spec: List[int], seed: bytes, indices: Sequence[int], q: int) -> List[int]:
    if any(v % q for v in spec):
        return spec

    if not indices:
        raise ValueError("empty support")

    digest = hashlib.sha256(seed + b"/fallback").digest()
    idx = indices[int.from_bytes(digest[:2], "little") % len(indices)]
    spec[idx] = 1
    return spec


def _special_constants(q: int) -> tuple[int, int, int, int, int]:
    g = primitive_root(q)
    root_minus_one = pow(g, (q - 1) // 4, q)
    if (root_minus_one * root_minus_one) % q != (q - 1) % q:
        raise ValueError("invalid sqrt(-1)")

    sigma_root = pow(g, (q - 1) // 8, q)
    sigma = (sigma_root * sigma_root) % q
    tau = pow(g, 73, q)
    return g, root_minus_one, sigma_root, sigma, tau


def _band_layout(seed: bytes, n: int) -> tuple[List[int], List[int], List[int], List[int], List[int]]:
    order = _rank_indices(seed, b"/band-layout", n)
    n0, n1, n2, n3 = AUX_BAND_SLOTS

    band0 = order[:n0]
    band1 = order[n0 : n0 + n1]
    band2 = order[n0 + n1 : n0 + n1 + n2]
    band3 = order[n0 + n1 + n2 : n0 + n1 + n2 + n3]
    live = order[n0 + n1 + n2 + n3 :]

    if len(live) != MAIN_SLOTS:
        raise ValueError("slot partition mismatch")

    return band0, band1, band2, band3, live


def _is_band0(u: int, v: int, q: int, sigma: int, tau: int) -> bool:
    del v, sigma, tau
    return (u * u + 1) % q == 0


def _is_band1(u: int, v: int, q: int, sigma: int, tau: int) -> bool:
    del u, tau
    return (v * v - sigma) % q == 0


def _is_band2(u: int, v: int, q: int, sigma: int, tau: int) -> bool:
    del sigma, tau
    return v % q == (u * u) % q


def _is_band3(u: int, v: int, q: int, sigma: int, tau: int) -> bool:
    del sigma
    return (u * v - tau) % q == 0


def classify_slot(u: int, v: int, q: int) -> int:
    _, _, _, sigma, tau = _special_constants(q)
    if _is_band0(u, v, q, sigma, tau):
        return 0
    if _is_band1(u, v, q, sigma, tau):
        return 1
    if _is_band2(u, v, q, sigma, tau):
        return 2
    if _is_band3(u, v, q, sigma, tau):
        return 3
    return 4


def _pick_value(seed: bytes, tag: bytes, idx: int, q: int, accept: Callable[[int], bool]) -> int:
    counter = 0
    while True:
        digest = hashlib.sha256(seed + tag + idx.to_bytes(4, "little") + counter.to_bytes(2, "little")).digest()
        v = (int.from_bytes(digest[:2], "little") % (q - 1)) + 1
        if accept(v):
            return v
        counter += 1


def expand_mask_spectra(
    n: int = N,
    q: int = Q,
    layout_seed: bytes = LAYOUT_SEED,
    mask_h_seed: bytes = MASK_H_SEED,
    mask_g_seed: bytes = MASK_G_SEED,
) -> tuple[List[int], List[int]]:
    band0, band1, band2, band3, live = _band_layout(layout_seed, n)
    _, root_minus_one, sigma_root, sigma, tau = _special_constants(q)

    h_hat: List[int] = [0] * n
    g_hat: List[int] = [0] * n

    for idx in band0:
        bit = hashlib.sha256(mask_h_seed + b"/band0/u" + idx.to_bytes(4, "little")).digest()[0] & 1
        u = root_minus_one if bit == 0 else (-root_minus_one) % q
        v = _pick_value(
            mask_g_seed,
            b"/band0/v",
            idx,
            q,
            lambda x, uu=u: not _is_band1(uu, x, q, sigma, tau)
            and not _is_band2(uu, x, q, sigma, tau)
            and not _is_band3(uu, x, q, sigma, tau),
        )
        h_hat[idx] = u
        g_hat[idx] = v

    for idx in band1:
        bit = hashlib.sha256(mask_g_seed + b"/band1/v" + idx.to_bytes(4, "little")).digest()[0] & 1
        v = sigma_root if bit == 0 else (-sigma_root) % q
        u = _pick_value(
            mask_h_seed,
            b"/band1/u",
            idx,
            q,
            lambda x, vv=v: not _is_band0(x, vv, q, sigma, tau)
            and not _is_band2(x, vv, q, sigma, tau)
            and not _is_band3(x, vv, q, sigma, tau),
        )
        h_hat[idx] = u
        g_hat[idx] = v

    for idx in band2:
        u = _pick_value(
            mask_h_seed,
            b"/band2/u",
            idx,
            q,
            lambda x: x != 0
            and (x * x + 1) % q != 0
            and ((x * x) % q) != sigma_root
            and ((x * x) % q) != (-sigma_root) % q
            and (x * ((x * x) % q) - tau) % q != 0,
        )
        v = (u * u) % q
        h_hat[idx] = u
        g_hat[idx] = v

    for idx in band3:
        def _accept_band3(x: int) -> bool:
            if x == 0 or (x * x + 1) % q == 0:
                return False
            vv = (tau * pow(x, -1, q)) % q
            if _is_band1(x, vv, q, sigma, tau):
                return False
            if _is_band2(x, vv, q, sigma, tau):
                return False
            return True

        u = _pick_value(mask_h_seed, b"/band3/u", idx, q, _accept_band3)
        v = (tau * pow(u, -1, q)) % q
        h_hat[idx] = u
        g_hat[idx] = v

    for idx in live:
        counter = 0
        while True:
            du = hashlib.sha256(
                mask_h_seed + b"/live/u" + idx.to_bytes(4, "little") + counter.to_bytes(2, "little")
            ).digest()
            dv = hashlib.sha256(
                mask_g_seed + b"/live/v" + idx.to_bytes(4, "little") + counter.to_bytes(2, "little")
            ).digest()
            u = (int.from_bytes(du[:2], "little") % (q - 1)) + 1
            v = (int.from_bytes(dv[:2], "little") % (q - 1)) + 1
            if classify_slot(u, v, q) == 4:
                h_hat[idx] = u
                g_hat[idx] = v
                break
            counter += 1

    return h_hat, g_hat


def expand_mask_polys(
    n: int = N,
    q: int = Q,
    layout_seed: bytes = LAYOUT_SEED,
    mask_h_seed: bytes = MASK_H_SEED,
    mask_g_seed: bytes = MASK_G_SEED,
) -> tuple[List[int], List[int]]:
    h_hat, g_hat = expand_mask_spectra(
        n=n,
        q=q,
        layout_seed=layout_seed,
        mask_h_seed=mask_h_seed,
        mask_g_seed=mask_g_seed,
    )
    return spec_inverse(h_hat, q=q), spec_inverse(g_hat, q=q)


def _sample_support_secret(
    seed: bytes,
    tag: bytes,
    support: Sequence[int],
    table: Sequence[int],
    n: int,
    q: int,
) -> List[int]:
    values = _sample_from_table(seed, tag, table, len(support), q)
    spec = [0] * n
    for idx, val in zip(support, values):
        spec[idx] = int(val % q)
    spec = _ensure_nonzero(spec, seed + tag, support, q)
    return spec_inverse(spec, q=q)


def sample_main_secret(seed: bytes, n: int = N, q: int = Q, layout_seed: bytes = LAYOUT_SEED) -> List[int]:
    _, _, _, _, live = _band_layout(layout_seed, n)
    return _sample_support_secret(
        seed=seed,
        tag=b"/main-secret",
        support=live,
        table=MAIN_VALUE_TABLE,
        n=n,
        q=q,
    )


def sample_blinds(seed: bytes, n: int = N, q: int = Q, layout_seed: bytes = LAYOUT_SEED) -> List[List[int]]:
    band0, band1, band2, band3, _ = _band_layout(layout_seed, n)
    supports = (band0, band1, band2, band3)
    out: List[List[int]] = []
    for i, (support, table) in enumerate(zip(supports, AUX_VALUE_TABLES)):
        out.append(
            _sample_support_secret(
                seed=seed,
                tag=f"/aux-{i}".encode(),
                support=support,
                table=table,
                n=n,
                q=q,
            )
        )
    return out


def sample_error(seed: bytes, n: int = N, q: int = Q, eta: int = ETA_E) -> List[int]:
    if eta != ETA_E:
        raise ValueError("spectral noise table is fixed for this challenge instance")

    e_hat = _sample_from_table(seed, b"/e-ntt", ERROR_VALUE_TABLE, n, q)
    return spec_inverse(e_hat, q=q)


def derive_symmetric_key(s_base: List[int], q: int) -> bytes:
    h = hashlib.sha256(poly_to_bytes(s_base, q)).digest()
    return h[:16]


def encrypt_flag_with_secret(flag: bytes, s_base: List[int], q: int) -> Tuple[bytes, bytes, bytes]:
    key = derive_symmetric_key(s_base, q)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(flag)
    return nonce, ct, tag


def decrypt_flag_with_secret(nonce: bytes, ct: bytes, tag: bytes, s_base: List[int], q: int) -> bytes:
    key = derive_symmetric_key(s_base, q)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


def random_uniform_poly(n: int, q: int) -> List[int]:
    raw = os.urandom(2 * n)
    out: List[int] = []
    for i in range(n):
        v = int.from_bytes(raw[2 * i : 2 * i + 2], "little")
        out.append(v % q)
    return out


def main_secret_coeff(sample_hat: Sequence[int], u: int, v: int, q: int) -> int:
    u2 = (u * u) % q
    v2 = (v * v) % q
    return (
        sample_hat[0]
        + u * sample_hat[1]
        + v * sample_hat[2]
        + u2 * sample_hat[3]
        + (u * v % q) * sample_hat[4]
        + v2 * sample_hat[5]
        + (u2 * v % q) * sample_hat[6]
    ) % q


def blind0_coeff(sample_hat: Sequence[int], u: int, v: int, q: int) -> int:
    return (sample_hat[7] + u * sample_hat[8] + v * sample_hat[9]) % q


def blind1_coeff(sample_hat: Sequence[int], u: int, v: int, q: int) -> int:
    return (sample_hat[10] + u * sample_hat[11] + v * sample_hat[12]) % q


def blind2_coeff(sample_hat: Sequence[int], u: int, v: int, q: int) -> int:
    return (sample_hat[13] + u * sample_hat[14] + v * sample_hat[15] + (u * v % q) * sample_hat[16]) % q


def blind3_coeff(sample_hat: Sequence[int], u: int, v: int, q: int) -> int:
    return (sample_hat[17] + u * sample_hat[18] + v * sample_hat[19] + (v * v % q) * sample_hat[20]) % q


def active_coeff(sample_hat: Sequence[int], band: int, u: int, v: int, q: int) -> int:
    if band == 0:
        return blind0_coeff(sample_hat, u, v, q)
    if band == 1:
        return blind1_coeff(sample_hat, u, v, q)
    if band == 2:
        return blind2_coeff(sample_hat, u, v, q)
    if band == 3:
        return blind3_coeff(sample_hat, u, v, q)
    return main_secret_coeff(sample_hat, u, v, q)


class Oracle:
    def __init__(self, inst: Instance):
        self.n = inst.n
        self.q = inst.q
        self.k = inst.k
        self.eta_s = inst.eta_s
        self.eta_e = inst.eta_e

        self.layout_seed = bytes.fromhex(inst.layout_seed_hex)
        self.mask_h_seed = bytes.fromhex(inst.mask_h_seed_hex)
        self.mask_g_seed = bytes.fromhex(inst.mask_g_seed_hex)

        self.h, self.g = expand_mask_polys(
            n=self.n,
            q=self.q,
            layout_seed=self.layout_seed,
            mask_h_seed=self.mask_h_seed,
            mask_g_seed=self.mask_g_seed,
        )

        self.h2 = poly_mul(self.h, self.h, q=self.q)
        self.hg = poly_mul(self.h, self.g, q=self.q)
        self.g2 = poly_mul(self.g, self.g, q=self.q)
        self.h2g = poly_mul(self.h2, self.g, q=self.q)

        self.s0 = [int(x) % self.q for x in inst.s_base]
        self.blinds = [[int(x) % self.q for x in poly] for poly in inst.blind_bases]
        if len(self.blinds) != 4:
            raise ValueError("expected exactly four auxiliary secrets")

        t0, t1, t2, t3 = self.blinds
        self.secrets: List[List[int]] = [
            self.s0,
            poly_mul(self.h, self.s0, q=self.q),
            poly_mul(self.g, self.s0, q=self.q),
            poly_mul(self.h2, self.s0, q=self.q),
            poly_mul(self.hg, self.s0, q=self.q),
            poly_mul(self.g2, self.s0, q=self.q),
            poly_mul(self.h2g, self.s0, q=self.q),
            t0,
            poly_mul(self.h, t0, q=self.q),
            poly_mul(self.g, t0, q=self.q),
            t1,
            poly_mul(self.h, t1, q=self.q),
            poly_mul(self.g, t1, q=self.q),
            t2,
            poly_mul(self.h, t2, q=self.q),
            poly_mul(self.g, t2, q=self.q),
            poly_mul(self.hg, t2, q=self.q),
            t3,
            poly_mul(self.h, t3, q=self.q),
            poly_mul(self.g, t3, q=self.q),
            poly_mul(self.g2, t3, q=self.q),
        ]
        if len(self.secrets) != self.k:
            raise ValueError("secret basis size does not match k")

        self.nonce = bytes.fromhex(inst.nonce_hex)
        self.ct = bytes.fromhex(inst.ct_hex)
        self.tag = bytes.fromhex(inst.tag_hex)

        self.pack_bits = 14
        self.pack_len = (self.n * self.pack_bits + 7) // 8

    def get_public(self) -> Dict[str, Any]:
        return {
            "version": VERSION,
            "n": self.n,
            "q": self.q,
            "k": self.k,
            "eta_s": self.eta_s,
            "eta_e": self.eta_e,
            "layout_seed_hex": self.layout_seed.hex(),
            "mask_h_seed_hex": self.mask_h_seed.hex(),
            "mask_g_seed_hex": self.mask_g_seed.hex(),
            "poly_pack": {"bits": self.pack_bits, "bytes": self.pack_len},
            "max_samples": MAX_SAMPLES,
        }

    def get_encrypted_flag(self) -> Dict[str, str]:
        return {
            "nonce_hex": self.nonce.hex(),
            "ct_hex": self.ct.hex(),
            "tag_hex": self.tag.hex(),
        }

    def sample(self) -> Dict[str, Any]:
        seed = os.urandom(32)
        a = [random_uniform_poly(self.n, self.q) for _ in range(self.k)]
        e = sample_error(seed, n=self.n, q=self.q, eta=self.eta_e)

        b = e
        for ai, si in zip(a, self.secrets):
            b = poly_add(b, poly_mul(ai, si, q=self.q), q=self.q)

        return {
            "a_hex": [pack_poly14(ai, self.q).hex() for ai in a],
            "b_hex": pack_poly14(b, self.q).hex(),
        }

    def check_secret(self, s_guess: List[int]) -> bool:
        if len(s_guess) != self.n:
            return False
        sg = [int(x) % self.q for x in s_guess]
        return sg == self.s0


def generate_instance(flag_path: str = FLAG_PATH, out_path: str = INSTANCE_PATH) -> Instance:
    if not os.path.exists(flag_path):
        raise FileNotFoundError(flag_path)

    flag = open(flag_path, "rb").read().strip()
    if not flag:
        raise ValueError("empty flag")

    master = os.urandom(32)

    s_base = sample_main_secret(master, n=N, q=Q, layout_seed=LAYOUT_SEED)
    blind_bases = sample_blinds(master, n=N, q=Q, layout_seed=LAYOUT_SEED)
    nonce, ct, tag = encrypt_flag_with_secret(flag, s_base, q=Q)

    inst = Instance(
        version=VERSION,
        n=N,
        q=Q,
        k=K,
        eta_s=ETA_S,
        eta_e=ETA_E,
        layout_seed_hex=LAYOUT_SEED.hex(),
        mask_h_seed_hex=MASK_H_SEED.hex(),
        mask_g_seed_hex=MASK_G_SEED.hex(),
        s_base=[int(x) for x in s_base],
        blind_bases=[[int(x) for x in poly] for poly in blind_bases],
        nonce_hex=nonce.hex(),
        ct_hex=ct.hex(),
        tag_hex=tag.hex(),
    )

    with open(out_path, "w") as f:
        json.dump(inst.__dict__, f)

    return inst


def load_instance(path: str = INSTANCE_PATH) -> Instance:
    with open(path, "r") as f:
        data = json.load(f)
    inst = Instance(**data)
    if inst.version != VERSION:
        raise ValueError("instance version mismatch")
    return inst


def _send_json(wfile, obj: Dict[str, Any]) -> None:
    wfile.write((json.dumps(obj) + "\n").encode())


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.server: "CTFServer"  # type: ignore

        self.wfile.write(BANNER.encode())
        self.wfile.write(b"\n")

        remaining = MAX_SAMPLES

        while True:
            try:
                self.wfile.write(MENU.encode())
                line = self.rfile.readline()
                if not line:
                    return
                choice = line.strip().decode(errors="ignore")

                if choice == "1":
                    _send_json(self.wfile, self.server.oracle.get_public())

                elif choice == "2":
                    if remaining <= 0:
                        _send_json(self.wfile, {"error": "sample limit reached"})
                        continue
                    remaining -= 1
                    _send_json(self.wfile, self.server.oracle.sample())

                elif choice == "3":
                    _send_json(self.wfile, self.server.oracle.get_encrypted_flag())

                elif choice == "4":
                    self.wfile.write(b"send JSON list of length N (secret base polynomial)\n> ")
                    raw = self.rfile.readline()
                    if not raw:
                        return
                    try:
                        arr = json.loads(raw.decode())
                        if not isinstance(arr, list):
                            raise ValueError("not a list")
                        ok = self.server.oracle.check_secret(arr)
                    except Exception:
                        ok = False

                    if ok:
                        flag = open(FLAG_PATH, "rb").read().strip()
                        _send_json(self.wfile, {"ok": True, "flag": flag.decode(errors="replace")})
                    else:
                        _send_json(self.wfile, {"ok": False})

                elif choice == "5":
                    self.wfile.write(b"bye\n")
                    return

                else:
                    _send_json(self.wfile, {"error": "unknown option"})

            except Exception as e:
                _send_json(self.wfile, {"error": str(e)})
                return


class CTFServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, server_address):
        try:
            if not os.path.exists(INSTANCE_PATH):
                raise FileNotFoundError(INSTANCE_PATH)
            inst = load_instance(INSTANCE_PATH)
        except Exception:
            inst = generate_instance(flag_path=FLAG_PATH, out_path=INSTANCE_PATH)
        self.oracle = Oracle(inst)
        super().__init__(server_address, Handler)


def build_instance_cmd(out_path: str = INSTANCE_PATH, flag_path: str = FLAG_PATH) -> None:
    inst = generate_instance(flag_path=flag_path, out_path=out_path)
    print(
        f"[+] wrote {out_path}: version={inst.version} n={inst.n} q={inst.q} "
        f"k={inst.k} eta_s={inst.eta_s} eta_e={inst.eta_e}"
    )


def serve_cmd(host: str, port: int) -> None:
    with CTFServer((host, port)) as srv:
        print(f"[+] listening on {host}:{port}")
        srv.serve_forever()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PQChat challenge server")
    sub = parser.add_subparsers(dest="cmd")

    build = sub.add_parser("build-instance", help="generate instance.json from flag.txt")
    build.add_argument("--out", default=INSTANCE_PATH)
    build.add_argument("--flag", default=FLAG_PATH)

    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", default=1337, type=int)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.cmd == "build-instance":
        build_instance_cmd(out_path=args.out, flag_path=args.flag)
        return
    serve_cmd(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
