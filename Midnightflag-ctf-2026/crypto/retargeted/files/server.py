#!/usr/bin/env python3
import hashlib
import secrets
import socketserver


P = 65993754221047993367757014757310801859001451513902355017284390150045199658079
Q = 32996877110523996683878507378655400929500725756951177508642195075022599829039
N = 32
MAX_Q = 4
HOST = "0.0.0.0"
PORT = 1337


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
        else:
            raise TypeError(type(part))
    return int.from_bytes(h.digest(), "big") % Q


def lift(label):
    ctr = 0
    while True:
        raw = hashlib.sha256(label + ctr.to_bytes(2, "big")).digest()
        x = int.from_bytes(raw, "big") % P
        if x < 2:
            ctr += 1
            continue
        y = pow(x, 2, P)
        if y != 1:
            return y
        ctr += 1


G = [lift(f"G/{i}".encode()) for i in range(N)]
HC = lift(b"H/coeff")
HE = lift(b"H/eval")
U = lift(b"U/eval")


BINOM = [[0] * N for _ in range(N)]
for i in range(N):
    BINOM[i][0] = 1
    BINOM[i][i] = 1
for i in range(2, N):
    for j in range(1, i):
        BINOM[i][j] = (BINOM[i - 1][j - 1] + BINOM[i - 1][j]) % Q


def vadd(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


def vsub(a, b):
    return [(x - y) % Q for x, y in zip(a, b)]


def vscale(k, a):
    return [(k * x) % Q for x in a]


def shift_taylor(a, delta):
    out = [0] * N
    pw = [1] * N
    for i in range(1, N):
        pw[i] = (pw[i - 1] * delta) % Q
    for k in range(N):
        acc = 0
        for j in range(k, N):
            acc += BINOM[j][k] * pw[j - k] * a[j]
        out[k] = acc % Q
    return out


def taylor_to_coeff(a, x):
    return shift_taylor(a, (-x) % Q)


def coeff_to_taylor(a, x):
    return shift_taylor(a, x)


def poly_eval(coeffs, x):
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % Q
    return acc


def coeff_commit(coeffs, blind):
    acc = pow(HC, blind % Q, P)
    for base, exp in zip(G, coeffs):
        acc = (acc * pow(base, exp % Q, P)) % P
    return acc


def eval_commit(y, blind):
    return (pow(U, y % Q, P) * pow(HE, blind % Q, P)) % P


def proof_chal(C, x, Y, A, B):
    return htag(b"chal", C, x, Y, A, B)


def ratchet_mu(x, Y, A, B):
    mu = htag(b"ratchet", x, Y, A, B)
    if mu == 0:
        mu = 1
    return mu


def ratchet_nu(x, Y, A, B, s, t):
    nu = htag(b"tail", x, Y, A, B, s, t)
    if nu == 0:
        nu = 1
    return nu


def jet_delta(x, Y, A, B, s, t):
    return htag(b"jet", x, Y, A, B, s, t)


def pack_vec(v):
    return " ".join(f"{x:x}" for x in v)


def unpack_scalar(s):
    s = s.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return int(s, 16) % Q


def verify(C, x, Y, A, B, w, s, t):
    c = proof_chal(C, x, Y, A, B)
    z = shift_taylor(w, (-jet_delta(x, Y, A, B, s, t)) % Q)
    lhs1 = coeff_commit(taylor_to_coeff(z, x), s)
    rhs1 = (A * pow(C, c, P)) % P
    lhs2 = eval_commit(z[0], t)
    rhs2 = (B * pow(Y, c, P)) % P
    return lhs1 == rhs1 and lhs2 == rhs2


class Box:
    def __init__(self):
        self.f = [secrets.randbelow(Q) for _ in range(N)]
        self.rho = secrets.randbelow(Q)
        self.C = coeff_commit(self.f, self.rho)
        self.admin_x = secrets.randbelow(Q - 1) + 1
        self.hist = []
        self.used = set()

    def _fresh_mask(self):
        return {
            "x": None,
            "u": [secrets.randbelow(Q) for _ in range(N)],
            "eta": secrets.randbelow(Q),
            "theta": secrets.randbelow(Q),
            "mu": None,
            "nu": None,
        }

    def _mask_for(self, x):
        if len(self.hist) < 3:
            st = self._fresh_mask()
            st["x"] = x
            return st
        oldest = self.hist[-3]
        older = self.hist[-2]
        newer = self.hist[-1]
        mu = older["mu"]
        nu = oldest["nu"]
        if mu is None or nu is None:
            raise RuntimeError("bad ratchet state")
        u = vadd(
            vadd(
                shift_taylor(newer["u"], (x - newer["x"]) % Q),
                vscale(mu, shift_taylor(older["u"], (x - older["x"]) % Q)),
            ),
            vscale(nu, shift_taylor(oldest["u"], (x - oldest["x"]) % Q)),
        )
        return {
            "x": x,
            "u": u,
            "eta": (newer["eta"] + mu * older["eta"] + nu * oldest["eta"]) % Q,
            "theta": (newer["theta"] + mu * older["theta"] + nu * oldest["theta"]) % Q,
            "mu": None,
            "nu": None,
        }

    def open_at(self, x):
        if len(self.hist) >= MAX_Q:
            raise ValueError("oracle exhausted")
        if x == self.admin_x:
            raise ValueError("admin point is reserved")
        if x in self.used:
            raise ValueError("point already used")
        st = self._mask_for(x)
        fx = coeff_to_taylor(self.f, x)
        y_blind = secrets.randbelow(Q)
        Y = eval_commit(fx[0], y_blind)
        A = coeff_commit(taylor_to_coeff(st["u"], x), st["eta"])
        B = eval_commit(st["u"][0], st["theta"])
        c = proof_chal(self.C, x, Y, A, B)
        z = vadd(st["u"], vscale(c, fx))
        s = (st["eta"] + c * self.rho) % Q
        t = (st["theta"] + c * y_blind) % Q
        w = shift_taylor(z, jet_delta(x, Y, A, B, s, t))
        if not verify(self.C, x, Y, A, B, w, s, t):
            raise RuntimeError("internal verify failed")
        st["mu"] = ratchet_mu(x, Y, A, B)
        st["nu"] = ratchet_nu(x, Y, A, B, s, t)
        self.hist.append(st)
        self.used.add(x)
        return {
            "x": x,
            "Y": Y,
            "A": A,
            "B": B,
            "w": w,
            "s": s,
            "t": t,
        }

    def redeem(self, guess):
        return guess % Q == poly_eval(self.f, self.admin_x)


class Handler(socketserver.StreamRequestHandler):
    def line(self, msg=""):
        self.wfile.write(msg.encode() + b"\n")
        self.wfile.flush()

    def ask(self, msg):
        self.wfile.write(msg.encode())
        self.wfile.flush()
        data = self.rfile.readline()
        if not data:
            raise EOFError
        return data.decode().strip()

    def handle(self):
        box = Box()
        self.line("jet audit gateway")
        self.line(f"C = {box.C:x}")
        self.line(f"admin_x = {box.admin_x:x}")
        self.line("")
        self.line("1) audited opening")
        self.line("2) redeem")
        self.line("3) quit")
        while True:
            try:
                choice = self.ask("> ")
            except EOFError:
                return
            if choice == "1":
                try:
                    raw = self.ask("x = ")
                    x = unpack_scalar(raw)
                    proof = box.open_at(x)
                    self.line(f"Y = {proof['Y']:x}")
                    self.line(f"A = {proof['A']:x}")
                    self.line(f"B = {proof['B']:x}")
                    self.line(f"s = {proof['s']:x}")
                    self.line(f"t = {proof['t']:x}")
                    self.line(f"w = {pack_vec(proof['w'])}")
                except Exception as e:
                    self.line(f"err: {e}")
            elif choice == "2":
                raw = self.ask("f(admin_x) = ")
                try:
                    guess = unpack_scalar(raw)
                    if box.redeem(guess):
                        with open("flag.txt", "r", encoding="utf-8") as fh:
                            self.line(fh.read().strip())
                    else:
                        self.line("no")
                except Exception:
                    self.line("bad input")
                return
            elif choice == "3":
                self.line("bye")
                return
            else:
                self.line("?")


class Threaded(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    with Threaded((HOST, PORT), Handler) as srv:
        srv.serve_forever()
