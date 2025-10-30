# Modular Inverse Hidden Number Problem

Modular Inverse Hidden Number Problem (MIHNP):

Given prime $p$, $\alpha$ is a hidden integer in $\mathbb{Z}_p$. We are given $n$ random integers $x_1, x_2, \cdots, x_n$ and corresponding $\mathrm{MSB}_k(1/(\alpha+x_i))$: the MSB bits of modular inverse of $\alpha + x_i$.

## Approach 1

Here is the first approach in paper [The Modular Inversion Hidden Number Problem](https://www.iacr.org/archive/asiacrypt2001/22480036.pdf). We are given:

$b_i = \mathrm{MSB}_k(1/(\alpha+x_i))$

Let $e_i = 1/(\alpha+x_i) - b_i$, so:

$(\alpha + x_i)(b_i + e_i) = 1 \pmod p$

Let $i = 0$, then:

$(\alpha + x_0)(b_0 + e_0) = 1 \pmod p$

Eliminate the known $\alpha$ from the equations:

$(b_0 + e_0) * (b_i + e_i) * (\alpha + x_i) = b_0 + e_0 \pmod p$

$(b_0 + e_0) * (b_i + e_i) * (\alpha + x_0) = b_i + e_i \pmod p$

Subtract the two equations:

$(b_0 + e_0) * (b_i + e_i) * (x_i - x_0) = b_0 + e_0 - b_i - e_i \pmod p$

Expand:

$ (x_i - x_0) * e_0 * e_i + (b_0 * x_i - b_0 * x_0 + 1) * e_i + (b_i * x_i - b_i * x_0 - 1) * e_0 + b_0 * b_i * (x_1 - x_0) + b_i - b_0 = 0 \pmod p$

Assign the coefficients for $e_0 * e_i$, $e_0$, $e_i$ and constant term:

$A_i = x_i - x_0$

$B_i = b_0 * x_i - b_0 * x_0 + 1$

$C_i = b_i * x_i - b_i * x_0 - 1$

$D_i = b_0 * b_i * (x_i - x_0) + b_i - b_0$

then,

$A_i * e_0 * e_i + B_i * e_i + C_i * e_0 + D_i = 0 \pmod p$

By definition, $e_i$ are small, so we are solving the modular equations with small roots. Given the bounds of $e_i$: $\mathrm{abs}(e_i) < B$, then we can create the following matrix to solve the modular equations for bounded small roots when $n=2$:

$$
M=\begin{pmatrix}
1 & & & & & & D_1 & D_2 \\
& 1/B & & & & & C_1 & C_2 \\
& & 1/B & & & & B_1 & \\
& & & 1/B & & & & B_2 \\
& & & & 1/B^2 & & A_1 & \\
& & & & & 1/B^2 & & A_2 \\
& & & & & & p & \\
& & & & & & & p \\
\end{pmatrix}
$$

The first row corresponds to the constant term: the coefficient is always 1. The second to fourth rows correspond to $e_0$ to $e_2$, they are bounded by $B$, so the coefficient is $1/B$ to make it small proportionally by $B$. The fifth to sixth rows correspond to $e_0e_1$ and $e_0e_2$, which are bounded by $B^2$. The last two rows are for the modular operation, where we can subtract by multiples of $p$.

Since the modular equations have the solution, we expect there is a vector $v$ in the lattice formed by $M$:

$v=(1, e_0/B, \cdots, e_n/B, e_0e_1/B^2, \cdots, e_0e_n/B^2, 0, \cdots, 0)$

which is a short vector and can be obtained by LLL reduction.

Code:

```python
from sage.all import *
from Crypto.Util.number import *
from pwn import *

# Modular Inversion Hidden Number Problem
p = getPrime(512)
k = 400
shift = p.bit_length() - k
alpha = getRandomRange(1, p)
x = []
b = []
for i in range(3):
    # (x_i, MSB_k((alpha + x_i)^{-1} \bmod p))
    x_i = getRandomRange(1, p)
    b_i = (pow(alpha + x_i, -1, p) >> shift) << shift
    x.append(x_i)
    b.append(b_i)


# https://www.iacr.org/archive/asiacrypt2001/22480036.pdf
# b_i = MSB_k((alpha + x_i)^{-1} \bmod p)
# e_i = ((alpha + x_i)^{-1} \bmod p) - b_i
# (b_i + e_i) * (alpha + x_i) = 1 \pmod p
# (b_0 + e_0) * (alpha + x_0) = 1 \pmod p
# eliminate alpha:
# (b_0 + e_0) * (b_i + e_i) * (alpha + x_i) = b_0 + e_0 \pmod p
# (b_0 + e_0) * (b_i + e_i) * (alpha + x_0) = b_i + e_i \pmod p
# subtract:
# (b_0 + e_0) * (b_i + e_i) * (x_i - x_0) = b_0 + e_0 - b_i - e_i \pmod p
# (x_i - x_0) * e_0 * e_i + (b_0 * x_i - b_0 * x_0 + 1) * e_i +
#   (b_i * x_i - b_i * x_0 - 1) * e_0 + b_0 * b_i * (x_1 - x_0) + b_i - b_0 = 0 \pmod p
# e_i are small: less than p >> shift
# A_i = x_i - x_0
# B_i = b_0 * x_i - b_0 * x_0 + 1
# C_i = b_i * x_i - b_i * x_0 - 1
# D_i = b_0 * b_i * (x_i - x_0) + b_i - b_0
# then
# A_i * e_0 * e_i + B_i * e_i + C_i * e_0 + D_i = 0 \pmod p


def attack(p, k, x, b):
    # compute A_i, B_i, C_i, and D_i
    n = len(x) - 1
    assert len(x) == len(b)
    A = []
    B = []
    C = []
    D = []
    for i in range(1, n + 1):
        A.append(x[i] - x[0])
        B.append(b[0] * x[i] - b[0] * x[0] + 1)
        C.append(b[i] * x[i] - b[i] * x[0] - 1)
        D.append(b[0] * b[i] * (x[i] - x[0]) + b[i] - b[0])

    # bound for e_i
    bound = p >> k

    # construct lattice
    M = [[0] * (3 * n + 2) for _ in range(3 * n + 2)]
    # row corresponds to 1
    M[0][0] = 1
    # D_1 to D_n
    for i in range(n):
        M[0][2 * n + 2 + i] = D[i]

    # rows correspond to e_i
    for i in range(n + 1):
        M[i + 1][i + 1] = Rational(1) / bound
        if i == 0:
            # C_1 to C_n for e_0
            for j in range(n):
                M[i + 1][2 * n + 2 + j] = C[j]
        else:
            # B_1 to B_n
            M[i + 1][2 * n + 2 + i - 1] = B[i - 1]

    # rows correspond to e_0 * e_i
    for i in range(n):
        M[n + 2 + i][n + 2 + i] = Rational(1) / bound / bound
        # A_1 to A_n
        M[n + 2 + i][2 * n + 2 + i] = A[i]

    # rows for the p term
    for i in range(n):
        M[2 * n + 2 + i][2 * n + 2 + i] = p

    M = Matrix(M)
    reduced = M.LLL()

    # find a row that satisfy:
    # v = (1, e_0 / bound, \cdots, e_n / bound, e_0 * e_1 / bound, \cdots, e_0 * e_n / bound, 0, \cdots, 0)
    for i in range(3 * n + 2):
        v = reduced[i]
        if (v[0] == 1 or v[0] == -1) and all(
            v[j] == 0 for j in range(2 * n + 2, 3 * n + 2)
        ):
            e_0 = v[0] * v[1] * bound
            # (b_0 + e_0) * (alpha + x_0) = 1 \pmod p
            alpha = (pow(int(b[0] + e_0), -1, p) - x[0]) % p
            # the answer may be incorrect...
            return alpha
    print("Failed to find answer in the following reduction result:")
    print(reduced)
    return None


assert attack(p, k, x, b) == alpha
```
