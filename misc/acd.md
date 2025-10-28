# Approximate Common Divisor

Reference: [Algorithms for the Approximate Common Divisor Problem](https://eprint.iacr.org/2016/215.pdf)

Problem: for unknown integer $p$, we are given some $pq + r$, where $q$ and $r$ are integers and $r$ are small: $\mathrm{abs}(r) < 2^{\rho}$. If without the $r$ term, we can simply compute GCD of many $pq$ to recover $p$. However, $r$ makes it approximate.

## Simultaneous Diophantine approximation approach (SDA)

We have $x_i = pq_i + r_i$ for $0 \le i \le t$ where $r_i$ is small. Then $x_i/x_0 \approx q_i/q_0$. If we can find $q_0$, then we can compute $r_0 = x_i \bmod q_0$ and $p = (x_0 - r_0) / q_0$.

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
print(f"Result correct:", res == p)
```

CTF challenges:

- [litt1e](../2025-10-26-xctf-final-2025/litt1e.md)
