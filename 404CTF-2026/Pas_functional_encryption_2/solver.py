#!/usr/bin/env sage
from sage.all import *
from Crypto.Random.random import randrange
import sys

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
K = GF(p)
a = K(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
b = K(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
E = EllipticCurve(K, (a, b))
order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
E.set_order(order)
K2 = GF(order)

INSTANCE_SIZE = 256
INSTANCE_TRIES = 64
TRIES = 7

def setup():
    g, h = E.random_element(), E.random_element()
    s = vector(K2, [K2.random_element() for _ in range(INSTANCE_SIZE)])
    t = vector(K2, [K2.random_element() for _ in range(INSTANCE_SIZE)])
    hi = [si * g + ti * h for si, ti in zip(s, t)]
    return g, h, hi, s, t

def keygen(s, t, x):
    return s * x, t * x

def encrypt(g, h, hi, y):
    r = K2.random_element()
    alpha = K2.random_element()
    alpha_g = alpha * g
    C = r * g
    D = r * h
    Ei = [yi * alpha_g + r * hi_el for yi, hi_el in zip(y, hi)]
    return C, D, Ei

def get_random_vector():
    return vector(K2, [randrange(0, 2) for _ in range(INSTANCE_SIZE)])


class ChallengeServer:
    def __init__(self):
        self.g, self.h, self.hi, self.s, self.t = setup()
        self.random_vector = None
        self.ciphertext = None
        self.rq = 0

    def action2(self):
        self.rq += 1
        if self.random_vector is None:
            self.random_vector = get_random_vector()
        if self.ciphertext is None:
            self.ciphertext = encrypt(self.g, self.h, self.hi, self.random_vector)
        result = (self.g, self.ciphertext)
        self._maybe_rekey()
        return result

    def action1(self):
        self.rq += 1
        y = get_random_vector()
        sx, tx = keygen(self.s, self.t, y)
        result = (self.g, y, sx, tx)
        self._maybe_rekey()
        return result

    def _maybe_rekey(self):
        if self.rq % INSTANCE_TRIES == 0:
            self.g, self.h, self.hi, self.s, self.t = setup()
            self.ciphertext = None

    def queries_left(self):
        return TRIES * INSTANCE_TRIES - self.rq

    def is_new_cycle(self):
        return self.rq % INSTANCE_TRIES == 0


def compute_T(y, sx, tx, C, D, Ei):
    T = E(0)
    for yi, ei in zip(y, Ei):
        if int(yi):
            T += ei
    T -= int(sx) * C + int(tx) * D
    return T

def recover_ds_from_cycle(cycle_raw):
    T_ref = None
    for y, T in cycle_raw:
        if T != E(0):
            T_ref = T
            break
    if T_ref is None:
        return []

    S = {}
    pt = E(0)
    for k in range(257):
        S[pt] = k
        pt = pt + T_ref

    d_ref = None
    nonzero_others = [(y, T) for y, T in cycle_raw if T != T_ref and T != E(0)]

    for candidate in range(1, 257):
        ok = True
        for _, T in nonzero_others[:5]:
            if candidate * T not in S:
                ok = False
                break
        if ok:
            d_ref = candidate
            break

    if d_ref is None:
        print("[!] d_ref not found for this cycle")
        return []

    results = []
    for y, T in cycle_raw:
        if T == E(0):
            d = 0
        else:
            scaled = d_ref * T
            if scaled not in S:
                continue
            d = S[scaled]
        results.append(([int(yi) for yi in y], d))

    return results


def solve():
    srv = ChallengeServer()
    all_samples = []

    print(f"[*] Part 2 attack: need {INSTANCE_SIZE} linearly independent samples")

    while len(all_samples) < INSTANCE_SIZE + 10 and srv.queries_left() > 1:
        g_cur, (C, D, Ei) = srv.action2()
        cycle_raw = []

        while not srv.is_new_cycle() and srv.queries_left() > 1:
            g_cur, y, sx, tx = srv.action1()
            T = compute_T(y, sx, tx, C, D, Ei)
            cycle_raw.append((y, T))
            if len(all_samples) + len(cycle_raw) >= INSTANCE_SIZE + 10:
                break

        recovered = recover_ds_from_cycle(cycle_raw)
        all_samples.extend(recovered)
        print(f"cycle done, total samples: {len(all_samples)}")

    print(f"[*] Solving {INSTANCE_SIZE}×{INSTANCE_SIZE} linear system...")
    use = all_samples[:INSTANCE_SIZE]
    A = matrix(ZZ, [y for y, _ in use])
    b_vec = vector(ZZ, [d for _, d in use])

    if A.rank() < INSTANCE_SIZE:
        print("[!] Matrix not full rank, trying to find independent subset")
        rows, ds = [], []
        M = matrix(ZZ, 0, INSTANCE_SIZE)
        for y, d in all_samples:
            M2 = M.stack(vector(ZZ, y))
            if M2.rank() > M.rank():
                M = M2
                rows.append(y)
                ds.append(d)
            if len(rows) == INSTANCE_SIZE:
                break
        A = matrix(ZZ, rows)
        b_vec = vector(ZZ, ds)

    rv_q = A.solve_right(b_vec.change_ring(QQ))
    rv = [int(round(float(x))) for x in rv_q]

    true_rv = [int(x) for x in srv.random_vector]
    print(f"[*] True rv (first 16): {true_rv[:16]}")
    print(f"[*] Recovered (first 16): {rv[:16]}")

    errors = sum(1 for a, b in zip(rv, true_rv) if a != b)
    if errors == 0:
        print("[+] SUCCESS, vectors match!")
    else:
        print(f"[-] FAIL, {errors} errors :(")
    return rv, true_rv

if __name__ == "__main__":
    solve()
