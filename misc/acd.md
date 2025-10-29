# Approximate Common Divisor

Reference: [Algorithms for the Approximate Common Divisor Problem](https://eprint.iacr.org/2016/215.pdf)

Approximate Common Divisor Problem: for unknown integer $p$, we are given some $pq_i + r_i$, where $q_i$ and $r_i$ are integers and $r_i$ are small: $\mathrm{abs}(r_i) < 2^{\rho}$. If without the $r_i$ term, we can simply compute GCD of many $pq_i$ to recover $p$. However, $r$ makes it approximate.

Partial Approximate Common Divisor Problem: $r_0 = 0$, so we have an exact multiple of $p$ given. Others are approximate.

CTF challenges:

- [litt1e](../2025-10-26-xctf-final-2025/litt1e.md)

## Simultaneous Diophantine Approximation approach (SDA)

We have $x_i = pq_i + r_i$ for $0 \le i \le t$ where $r_i$ is small. Then $x_i/x_0 \approx q_i/q_0$. If we can find $q_0$, then we can compute $r_0 = x_0 \bmod q_0$ and $p = (x_0 - r_0) / q_0$.

To find $q_0$ where there is approximation for all $x_i/x_0 \approx q_i/q_0$ equations, construct lattice:

$v_0 = (2^{\rho+1}, x_1, x_2, \cdots, x_t)$

$v_1 = (0, -x_0, 0, \cdots, 0)$

$v_t = (0, 0, 0, \cdots, -x_0)$

Run LLL reduction on the vectors. It will find the approximations of $q_i$ for us: $q_0v_0+q_1v_1+\cdots+q_tv_t$ is a short vector. Then we can recover $q_0$ by dividing the first entry by $2^{\rho+1}$.

Code:

```python
from sage.all import *
from Crypto.Util.number import *
import random

p = getPrime(512)
limit = 2**200
known = [random.randrange(1, p) * p + random.randrange(1, limit) for i in range(5)]


def sda_attack(known, limit):
    # Simultaneous Diophantine approximation approach (SDA)

    # try to use different elements as x_0
    for k in range(len(known)):
        known_new = known.copy()
        known_new[0], known_new[k] = known_new[k], known_new[0]

        # create matrix
        # limit*2,  x_1,  x_2, ..., x_t
        #       0, -x_0, ...
        #       0,    0, -x_0, ...
        #       ...
        #       0,    0,       ...,   0
        size = len(known_new)
        matrix = [[0] * size for _ in range(size)]
        matrix[0][0] = limit * 2
        for i in range(len(known_new) - 1):
            matrix[0][i + 1] = known_new[i + 1]
            matrix[i + 1][i + 1] = -known_new[0]

        B = Matrix(matrix)
        reduced = B.LLL()

        # recover q_0
        assert reduced[0][0] % (limit * 2) == 0
        q_0 = reduced[0][0] // (limit * 2)
        r_0 = known_new[0] % q_0

        assert (known_new[0] - r_0) % q_0 == 0
        p = abs(known_new[0] - r_0) // q_0

        # validate
        bad = False
        for k in known:
            if k % p >= limit:
                # bad guess
                bad = True
                break

        if bad:
            continue

        return p

    return None


res = sda_attack(known, limit)
print(f"Got result:", res != None)
# Note: sometimes it may give wrong but valid result
print(f"Result correct:", res == p)
```

## Orthogonal based approach (OL)

Create a lattice according to the paper, and for the $t-1$ short vectors in the lattice, $v_0 = \Sigma u_i r_i$ and $0 = \Sigma u_iq_i$, where $v_0$ is the first entry of the short vector, and $u_i$ are the coefficient of each basis vector. So we got $t-1$ vectors that are orthogonal to the vector of $(q_0, q_1, \cdots, q_t)$. We can compute the $q_i$ by finding the kernel of the vector subspace spanned by $u_i$ vectors. Then, we can recover $q$ in a similar way as previous.

```python
from sage.all import *
from Crypto.Util.number import *
import random

p = getPrime(512)
limit = 2**200
known = [random.randrange(1, p) * p + random.randrange(1, limit) for i in range(5)]

def ol_attack(known, limit):
    # Orthogonal based approach

    # create matrix
    # x_1, R, 0, ..., 0
    # x_2, 0, R, ..., 0
    # ...
    # x_t, 0, 0, ..., R
    R = limit
    size = len(known)
    matrix = [[0] * (size + 1) for _ in range(size)]
    for i in range(size):
        matrix[i][0] = known[i]
        matrix[i][i + 1] = R

    B = Matrix(matrix)
    # transform * B == reduced
    reduced, transform = B.LLL(transformation=True)
    assert transform * B == reduced

    # now v_0 = sum(u_i * r_i) for short enough vector
    # 0 = sum(u_i * q_i)

    # find kernel of the space spanned by t-1 u vectors
    M = transform[: size - 1][:]
    # q is the kernel
    q = M.right_kernel()
    q_0 = q.basis()[0][0]

    # r_0 = x_0 mod q_0
    r_0 = known[0] % q_0
    # p = (x_0 - r_0) // q_0
    p = (known[0] - r_0) // q_0

    return p


res = ol_attack(known, limit)
print(f"Got result:", res != None)
print(f"Result correct:", res == p)
```
