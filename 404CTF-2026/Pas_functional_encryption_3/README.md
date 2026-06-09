🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Writeup: Pas Functional Encryption (Part 3)

## Context

The scheme remains identical to the previous parts (IPFE on NIST P-256), but two changes break the part 2 attack. The secret vector to recover is now $\text{rv} \in \{0,1\}^{255} \times \{1\}$: the last bit is **fixed to 1**. The key query vectors are generated with **noise** on the last coordinate:

$$y = (y_0, \ldots, y_{254}, a) \quad \text{where } a \xleftarrow{\$} \mathbb{F}_n$$

The encryption remains the same as in part 2 ($E_i = (\alpha \cdot y_i) \cdot g + r \cdot h_i$), so decrypting a key query still yields $T = d \cdot G'$ with $G' = \alpha \cdot g$, but now:

$$T = \bigl(\underbrace{y[:255] \cdot \text{rv}[:255]}_{d_{\text{bin}} \in \{0..255\}} + \underbrace{a}_{\text{known, huge}}\bigr) \cdot G'$$

The term $a$ is known (returned by the server), but it is random in $\mathbb{F}_n$, so $T$ looks like a random EC point. We can no longer build a bounded table and do a direct search.

## The Server

`TRIES = 5`, `INSTANCE_TRIES = 64` → 320 queries, re-keying every 64. The ciphertext is cached exactly as in part 2: $\alpha$ and $G'$ are constant within a cycle.

## The Vulnerability

The vulnerability is the same as in part 2: $G' = \alpha \cdot g$ is **constant within a cycle**. All $T_i = (d_i + a_i) \cdot G'$ share the same unknown base. But since $a_i$ is large, we can no longer normalize directly.

The idea is to **recover $G'$ explicitly** using a meet-in-the-middle on two queries from the same cycle.

## Exploitation

### Step 1: Recover $G'$ via meet-in-the-middle

For two queries $i$ and $j$ from the same cycle:

$$T_i = (d_i + a_i) \cdot G', \qquad T_j = (d_j + a_j) \cdot G'$$

where $a_i, a_j$ are known and $d_i, d_j \in \{0..255\}$ are unknown. Eliminating $G'$:

$$d_j \cdot T_i - d_i \cdot T_j = a_i \cdot T_j - a_j \cdot T_i =: R$$

$R$ is a fully computable EC point. The equation rewrites as:

$$d_j \cdot T_i = R + d_i \cdot T_j$$

We then set up the meet-in-the-middle:
- **Baby steps**: precompute $\mathcal{L} = \{k \cdot T_j \mapsto k : k = 0..255\}$
- **Giant steps**: for $d_j = 0..255$, test if $R + d_j \cdot T_i \in \mathcal{L}$

A collision directly gives $(d_i, d_j)$, and thus:

$$G' = (d_i + a_i)^{-1} \cdot T_i$$

512 EC operations suffice, and the collision is unique with overwhelming probability.

### Step 2: Recover $d_k$ for all other queries

Once $G'$ is known, for each query $k$ in the cycle:

$$P_k = T_k - a_k \cdot G' = d_k \cdot G'$$

$d_k \in \{0..255\}$: precompute $\{k \cdot G' : k = 0..255\}$ and read off $d_k$ directly.

### Step 3: Solve the linear system

We accumulate pairs $(y_i[:255] \in \{0,1\}^{255},\ d_i)$ over the 5 cycles (rv constant, $\alpha/g/s/t$ change). We already know $\text{rv}[255] = 1$, so the system to solve is of size $255 \times 255$:

$$A \cdot \text{rv}[:255] = b$$

We solve over $\mathbb{Q}$, round to $\{0,1\}$, and append the last bit: $\text{rv} = \text{rv}[:255] + [1]$.

With $5 \times 63 = 315$ samples available, we comfortably exceed the 255 equations needed.

## Conclusion

The noise protection ($a \in \mathbb{F}_n$) attempts to make the $T_i$ indistinguishable from random points. But since $a_i$ is **known** and all $T_i$ within a cycle share the same $G'$, the relation $d_j \cdot T_i - d_i \cdot T_j = R$ (whose right-hand side is computable) reduces the problem to a meet-in-the-middle over $\{0..255\}^2$. Once $G'$ is explicitly recovered, the rest of the attack is identical to the previous parts.

---

#NOTE:

I started by writing a local solver, which you can read [here](solver.py). I won't include the remote solver here but the idea remains the same as for challenge 2.
