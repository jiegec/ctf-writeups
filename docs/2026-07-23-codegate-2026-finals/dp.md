# DP

```text
I lost a chunk of dp somewhere in the middle. Can you help me find it?
nc 15.165.7.186 8080
```

Attachment: `chal.py`

```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long


E = 257
OFFSET = 291
WIDTH = 444


flag = open("flag.txt", "rb").read().strip()
m = bytes_to_long(flag)

key = RSA.generate(2048, e=E)
n, p, e, d = int(key.n), int(key.p), int(key.e), int(key.d)

dp = d % (p - 1)
mask = ((1 << WIDTH) - 1) << OFFSET
dp_leak = dp & ~mask

c = pow(m, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
print(f"dp_leak = {dp_leak}")
```

## Solution

$d_p = d \bmod (p-1)$ is one of the CRT exponents used in RSA decryption. The leak zeroes out bits 291–734 (444 bits) of $d_p$:

$$
d_p = d_p^{\text{leak}} + x \cdot 2^{291}, \quad 0 \le x < 2^{444}
$$

From RSA we have $e \cdot d \equiv 1 \pmod{\phi(n)}$, which implies $e \cdot d_p \equiv 1 \pmod{p-1}$:

$$
e \cdot d_p = 1 + k \cdot (p-1) \quad \text{for some integer } k
$$

Since $d_p < p-1$, we have $k < e = 257$.

Substituting $d_p = d_p^{\text{leak}} + x \cdot 2^{291}$:

$$
e \cdot d_p^{\text{leak}} + e \cdot x \cdot 2^{291} + k - 1 = k \cdot p
$$

Let $A_k = e \cdot d_p^{\text{leak}} + k - 1$, $B = e \cdot 2^{291}$. Then:

$$
A_k + B \cdot x = k \cdot p
$$

Reducing modulo $p$ (since $k \cdot p \equiv 0 \pmod{p}$):

$$
A_k + B \cdot x \equiv 0 \pmod{p}
$$

This is a linear polynomial in $x$ with a root modulo $p$, where $p \mid n$. The root $x$ is bounded by $X = 2^{444}$. Coppersmith's theorem guarantees finding roots $x < n^{\beta^2}$ where $\beta = \log_p(n) \approx 0.5$. Since $n^{0.25} \approx 2^{512} > 2^{444}$, the root is recoverable.

For each candidate $k \in [1, 256]$, set up the monic polynomial $f_k(x) = x + A_k \cdot B^{-1} \bmod n$ and call Sage's `small_roots(X=2^444, beta=0.49)`. The correct $k$ yields the missing bits $x$, giving $p = (A_k + B \cdot x) / k$.

With $p$ known, factoring $n$ and decrypting $c$ yields the flag.

## Code

```python
# assign n, e, c, dp_leak from remote

P.<x> = PolynomialRing(Zmod(n))
X = 2^444
B = e * 2^291
B_inv = inverse_mod(B, n)

for k in range(1, e):
    A = e * dp_leak + k - 1
    cc = (A * B_inv) % n
    f = x + cc
    roots = f.small_roots(X=X, beta=0.49, epsilon=0.05)
    for x0 in roots:
        x0 = int(x0)
        p = (A + B * x0) // k
        if n % p == 0:
            q = n // p
            phi = (p - 1) * (q - 1)
            d = inverse_mod(e, phi)
            m = power_mod(c, d, n)
            flag = int(m).to_bytes((int(m).bit_length() + 7) // 8, 'big')
            print(flag.decode())
            exit()
```
