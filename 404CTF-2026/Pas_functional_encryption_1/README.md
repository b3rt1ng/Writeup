🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Writeup: Pas Functional Encryption

## Context

The challenge implements an Inner Product Functional Encryption scheme (IPFE), as described in [eprint 2015/608](https://eprint.iacr.org/2015/608.pdf), over the NIST P-256 curve.

Parameters:

- two random generators $g, h$ on the curve $E$
- a master key consisting of two secret vectors $s, t \in \mathbb{F}_q^{256}$
- public parameters $h_i = s_i \cdot g + t_i \cdot h$

Encryption of a binary vector $y$ (with random $r$):

$$C = r \cdot g, \quad D = r \cdot h, \quad E_i = y_i \cdot g + r \cdot h_i$$

Functional key generation for a vector $x$:

$$sk_x = (s \cdot x,\ t \cdot x)$$

Decryption with $sk_x = (sx, tx)$:

$$\sum_i x_i E_i - sx \cdot C - tx \cdot D = (x \cdot y) \cdot g$$

All that remains is to solve a discrete logarithm to recover $x \cdot y$, which is only feasible if this value stays small.

## The Server

The menu offers three actions:

1. **Get a key for a vector**: the server itself draws a random binary vector $x$ and returns $\{g, sx, tx, x\}$, i.e. the functional key **and** the plaintext vector
2. **Get an encrypted vector**: encrypts a single random secret binary vector (the target to recover) and returns $(C, D, E_i)$
3. **Check**: you must guess this secret vector exactly to get the flag

## The Vulnerability

In a properly used IPFE, the key generation oracle should only respond to queries for functions chosen by the attacker, and even then with strong restrictions to avoid leaking information about the encrypted vector.

Here, the server generates the vector $x$ used for the key itself... and gives it directly in plaintext alongside $sk_x$. Each call to option 1 therefore freely provides a pair $(x_i, sk_{x_i})$, allowing the computation of:

$$T = \sum_k x_i[k]\, E_k - sx_i \cdot C - tx_i \cdot D = (x_i \cdot \text{secret}) \cdot g$$

Since `secret` and each $x_i$ are binary vectors of length 256, the inner product $d_i = x_i \cdot \text{secret}$ is an integer between 0 and 256. The discrete logarithm becomes trivial: simply precompute $0 \cdot g, 1 \cdot g, \dots, 256 \cdot g$ and compare.

## Exploitation

By repeating operation 1 about 298 times, we obtain a linear system $A v = b$ where:

- each row of $A$ is a known binary vector $x_i$
- $b_i = d_i = x_i \cdot \text{secret}$
- $v = \text{secret}$ is the unknown to recover

The matrix $A$ (256 columns, enough rows) is invertible with high probability. We solve the system over $\mathbb{Q}$, round each coordinate to 0 or 1, and obtain the complete secret vector. All that's left is to submit it via option 3 to retrieve the flag.

## Conclusion

The vulnerability comes down to a single line: the key generation oracle leaks the random vector used in addition to the functional key itself. A scheme meant to only reveal *chosen* inner products thus becomes an oracle for *known* linear measurements of the secret, allowing complete reconstruction through simple linear algebra.
