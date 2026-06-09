🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Writeup: Pas Functional Encryption (Part 2)

## Context

The challenge reuses the same IPFE scheme on NIST P-256 as in part 1, with one important change in the encryption. The secret vector $\text{rv} \in \{0,1\}^{256}$ is encrypted as follows (with random $r, \alpha$):

$$C = r \cdot g, \quad D = r \cdot h, \quad E_i = y_i \cdot (\alpha \cdot g) + r \cdot h_i$$

The functional key for a vector $x$ remains the same:

$$sk_x = (s \cdot x,\ t \cdot x)$$

Decryption now yields:

$$\sum_i x_i E_i - sx \cdot C - tx \cdot D = (x \cdot y) \cdot \alpha g = d \cdot G'$$

where $G' = \alpha \cdot g$ is an **unknown, random point**. Unlike part 1, the result is no longer a known multiple of $g$: the information about $d$ is masked by $\alpha$.

## The Server

The menu exposes the same three actions as in part 1, with a budget constraint: `TRIES = 7` cycles of `INSTANCE_TRIES = 64` queries each, for a total of 448 queries. At each new cycle, the parameters $g, h, s, t$ are regenerated (re-keying), but the secret vector $\text{rv}$ remains the same.

## The Vulnerability

The server caches the ciphertext between calls to action 2 within the same cycle:

```python
if ciphertext is None:
    ciphertext = encrypt(g, h, hi, random_vector)
```

Consequence: within a given cycle, $\alpha$ is **fixed** and therefore $G' = \alpha \cdot g$ is constant. All decryption results $T_i = d_i \cdot G'$ are multiples of the same unknown point. Their ratios are preserved:

$$d_{\text{ref}} \cdot T_j = d_j \cdot T_{\text{ref}}$$

It is therefore possible to recover the values $d_i = x_i \cdot \text{rv}$ without ever knowing $\alpha$.

## Exploitation

For each cycle, we start by calling action 2 to fix the ciphertext (and thus $\alpha$), then call action 1 for the remaining 63 times. For each pair $(x_i, sk_{x_i})$ received, we compute $T_i = d_i \cdot G'$ by decryption.

We choose any non-zero $T_{\text{ref}}$ among the cycle's results. We precompute the set $\{k \cdot T_{\text{ref}} : k = 0..256\}$, then recover $d_{\text{ref}}$ (the unknown integer associated with $T_{\text{ref}}$) by finding the candidate $c \in \{1..256\}$ such that $c \cdot T_j$ belongs to this set for a handful of non-zero $T_j$. We then derive all $d_i$ via $d_i = S[d_{\text{ref}} \cdot T_i]$.

After 7 cycles, we have $7 \times 63 = 441$ pairs $(x_i, d_i)$. We select 256 linearly independent vectors $x_i$ to form the system:

$$A \cdot \text{rv} = b$$

We solve over $\mathbb{Q}$, round to $\{0, 1\}$, and submit the result via action 3 to obtain the flag.

## Conclusion

The vulnerability stems from the ciphertext cache: by fixing $\alpha$ for an entire cycle, the server makes the decryption results collinear. This coherence allows normalizing the $d_i$ without knowing $G'$, turning what seemed like a protection (the mask $\alpha$) into a silent constant. The exploitation then remains identical to part 1: linear algebra on accumulated measurements.

#NOTE:

I started by writing a local solver, which you can read [here](solver.py). To retrieve the flag, you need to interact with a netcat server, and for that we'll use [pwntools](https://docs.pwntools.com/en/stable/) to automate CLI interactions — you can see that solver [here](solve_remote.py)
