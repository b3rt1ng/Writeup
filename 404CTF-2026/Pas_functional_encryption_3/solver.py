#!/usr/bin/env python3

from sage.all import *
from Crypto.Random.random import randrange
import json, sys

p     = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
K     = GF(p)
a_c   = K(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
b_c   = K(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
E     = EllipticCurve(K, (a_c, b_c))
order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
E.set_order(order)
K2    = GF(order)

INSTANCE_SIZE  = 256
INSTANCE_TRIES = 64
TRIES          = 5

def setup():
    g, h = E.random_element(), E.random_element()
    s = vector(K2, [K2.random_element() for _ in range(INSTANCE_SIZE)])
    t = vector(K2, [K2.random_element() for _ in range(INSTANCE_SIZE)])
    hi = [g * si + h * ti for si, ti in zip(s, t)]
    return g, h, hi, s, t

def keygen(s, t, x):
    return s * x, t * x

def encrypt(g, h, hi, y):
    r = K2.random_element()
    alpha = K2.random_element()
    C = r * g
    D = r * h
    Ei = [(alpha * yi) * g + r * hi_el for yi, hi_el in zip(y, hi)]
    return C, D, Ei

def get_random_vector():
    return vector(K2, [randrange(0, 2) for _ in range(INSTANCE_SIZE - 1)] + [1])

def get_random_noisy_vector():
    return vector(K2, [randrange(0, 2) for _ in range(INSTANCE_SIZE - 1)]
                      + [randrange(0, int(E.order()))])

class ChallengeServer:
    def __init__(self):
        self.g, self.h, self.hi, self.s, self.t = setup()
        self.random_vector = None
        self.ciphertext    = None
        self.rq            = 0

    def action2(self):
        self.rq += 1
        if self.random_vector is None:
            self.random_vector = get_random_vector()
        if self.ciphertext is None:
            self.ciphertext = encrypt(self.g, self.h, self.hi, self.random_vector)
        res = (self.g, self.ciphertext)
        self._maybe_rekey()
        return res

    def action1(self):
        self.rq += 1
        y = get_random_noisy_vector()
        sx, tx = keygen(self.s, self.t, y)
        res = (self.g, y, sx, tx)
        self._maybe_rekey()
        return res

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
        yi_int = int(yi)
        if yi_int:
            T += yi_int * ei
    T -= int(sx) * C + int(tx) * D
    return T

def find_G_prime(cycle_raw):
    nonzero = [(y, T) for y, T in cycle_raw if T != E(0)]
    if len(nonzero) < 2:
        return None

    (y_i, T_i) = nonzero[0]
    (y_j, T_j) = nonzero[1]
    a_i = int(y_i[INSTANCE_SIZE - 1])
    a_j = int(y_j[INSTANCE_SIZE - 1])

    R = a_j * T_i - a_i * T_j

    L = {}
    pt = E(0)
    for k in range(256):
        L[pt] = k
        pt = pt + T_j

    pt = R
    for d_j in range(256):
        if pt in L:
            d_i = L[pt]
            scalar = K2(d_i) + K2(a_i)
            if scalar == 0:
                pt = pt + T_i
                continue
            G_prime = int(~scalar) * T_i
            return G_prime
        pt = pt + T_i

    return None

def recover_ds(cycle_raw, G_prime):
    table = {}
    pt = E(0)
    for k in range(256):
        table[pt] = k
        pt = pt + G_prime

    results = []
    for y, T in cycle_raw:
        P = T - int(y[INSTANCE_SIZE - 1]) * G_prime
        d = table.get(P)
        if d is not None:
            results.append(([int(yi) for yi in y[:INSTANCE_SIZE - 1]], d))
    return results

def solve():
    srv = ChallengeServer()
    all_samples = []
    needed = INSTANCE_SIZE - 1
    print(f"[*] Part 3 attack: need {needed} samples, have {TRIES*INSTANCE_TRIES} queries")

    while len(all_samples) < needed + 10 and srv.queries_left() > 1:
        _, (C, D, Ei) = srv.action2()
        cycle_raw = []

        while not srv.is_new_cycle() and srv.queries_left() > 1:
            _, y, sx, tx = srv.action1()
            T = compute_T(y, sx, tx, C, D, Ei)
            cycle_raw.append((y, T))
            if len(all_samples) + len(cycle_raw) >= needed + 10:
                break

        G_prime = find_G_prime(cycle_raw)
        if G_prime is None:
            print("[!] Could not find G' for this cycle, skipping")
            continue

        recovered = recover_ds(cycle_raw, G_prime)
        all_samples.extend(recovered)
        print(f"    cycle done, total samples: {len(all_samples)}")

    # Solve A * rv[:255] = b  over QQ
    print("[*] Solving linear system...")
    A     = matrix(ZZ, [y for y, _ in all_samples[:needed]])
    b_vec = vector(ZZ, [d for _, d in all_samples[:needed]])

    if A.rank() < needed:
        print("[!] Not full rank, picking independent rows...")
        rows, ds, M = [], [], matrix(ZZ, 0, needed)
        for y, d in all_samples:
            M2 = M.stack(vector(ZZ, y))
            if M2.rank() > M.rank():
                M = M2; rows.append(y); ds.append(d)
            if len(rows) == needed:
                break
        A     = matrix(ZZ, rows)
        b_vec = vector(ZZ, ds)

    rv_q   = A.solve_right(b_vec.change_ring(QQ))
    rv_255 = [int(round(float(x))) for x in rv_q]
    rv     = rv_255 + [1]

    true_rv = [int(x) for x in srv.random_vector]
    print(f"[*] True rv     (first 16): {true_rv[:16]}")
    print(f"[*] Recovered   (first 16): {rv[:16]}")

    errors = sum(1 for a, b in zip(rv, true_rv) if a != b)
    if errors == 0:
        print("[+] SUCCESS!")
    else:
        print(f"[-] FAIL: {errors} errors")

    return rv, true_rv

if __name__ == "__main__":
    solve()