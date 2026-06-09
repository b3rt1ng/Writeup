#!/usr/bin/env python3
from sage.all import *
from pwn import *
import json, sys

p     = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
K     = GF(p)
a     = K(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
b_    = K(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
E     = EllipticCurve(K, (a, b_))
order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
E.set_order(order)

INSTANCE_SIZE  = 256
INSTANCE_TRIES = 64
TRIES          = 7

def pt(xy):
    return E(xy[0], xy[1])

def compute_T(y_vec, sx, tx, C, D, Ei):
    T = E(0)
    for yi, ei in zip(y_vec, Ei):
        if yi:
            T += ei
    T -= int(sx) * C + int(tx) * D
    return T

def recover_ds(cycle_raw):
    T_ref = next((T for _, T in cycle_raw if T != E(0)), None)
    if T_ref is None:
        return []

    S = {}
    cur = E(0)
    for k in range(257):
        S[cur] = k
        cur = cur + T_ref

    others = [T for _, T in cycle_raw if T != T_ref and T != E(0)]
    d_ref = None
    for cand in range(1, 257):
        if all(cand * T in S for T in others[:5]):
            d_ref = cand
            break
    if d_ref is None:
        print("[!] d_ref not found for this cycle")
        return []

    results = []
    for y, T in cycle_raw:
        d = 0 if T == E(0) else S.get(d_ref * T)
        if d is not None:
            results.append((y, d))
    return results

def recv_json(r):
    while True:
        line = r.recvline(timeout=15).strip()
        if line.startswith(b'{'):
            return json.loads(line.decode())

def get_ciphertext(r):
    r.sendlineafter(b">>> ", b"2")
    data = recv_json(r)
    C  = pt(data["C"])
    D  = pt(data["D"])
    Ei = [pt(e) for e in data["Ei"]]
    return C, D, Ei

def get_key_query(r, C, D, Ei):
    r.sendlineafter(b">>> ", b"1")
    data = recv_json(r)
    y  = data["y"]
    sx = data["sx"]
    tx = data["tx"]
    T  = compute_T(y, sx, tx, C, D, Ei)
    return y, T

def solve_remote(host, port):
    r = remote(host, port)
    all_samples = []
    rq = 0

    print(f"[*] Connected to {host}:{port}")
    print(f"[*] Need {INSTANCE_SIZE} samples, have {TRIES * INSTANCE_TRIES} queries")

    while len(all_samples) < INSTANCE_SIZE + 10 and rq < TRIES * INSTANCE_TRIES - 2:
        C, D, Ei = get_ciphertext(r)
        rq += 1
        cycle_raw = []

        while rq % INSTANCE_TRIES != 0 and rq < TRIES * INSTANCE_TRIES - 2:
            y, T = get_key_query(r, C, D, Ei)
            rq += 1
            cycle_raw.append((y, T))
            if len(all_samples) + len(cycle_raw) >= INSTANCE_SIZE + 10:
                break

        recovered = recover_ds(cycle_raw)
        all_samples.extend(recovered)
        print(f"cycle done (rq={rq}), total samples: {len(all_samples)}")

    print("[*] Solving linear system...")
    A     = matrix(ZZ, [y for y, _ in all_samples[:INSTANCE_SIZE]])
    b_vec = vector(ZZ, [d for _, d in all_samples[:INSTANCE_SIZE]])

    if A.rank() < INSTANCE_SIZE:
        print("[!] Not full rank, picking independent rows...")
        rows, ds, M = [], [], matrix(ZZ, 0, INSTANCE_SIZE)
        for y, d in all_samples:
            M2 = M.stack(vector(ZZ, y))
            if M2.rank() > M.rank():
                M = M2; rows.append(y); ds.append(d)
            if len(rows) == INSTANCE_SIZE:
                break
        A     = matrix(ZZ, rows)
        b_vec = vector(ZZ, ds)

    rv_q = A.solve_right(b_vec.change_ring(QQ))
    rv   = [int(round(float(x))) for x in rv_q]
    print(f"[*] Recovered (first 16): {rv[:16]}")

    r.sendlineafter(b">>> ", b"3")
    r.sendlineafter(b">>> ", json.dumps(rv).encode())

    response = r.recvall(timeout=10).decode()
    print(f"\n[*] Server response:\n{response}")
    r.close()

if __name__ == "__main__":
    # I use this base for my others cripts that needs to interact with the remote servers of the 404 ctf
    HOST = sys.argv[1] if len(sys.argv) > 1 else "challenge.404ctf.fr"
    PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 10002
    solve_remote(HOST, PORT)
