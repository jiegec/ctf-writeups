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
from Crypto.Util.number import getPrime
import random


def matrix_lll(matrix: list[list[int]], transform: bool = False):
    """
    Compute LLL reduction on the given matrix.

    Args:
        matrix (list[list[int]]): the row-major two-dimensional integer matrix
        transform (bool): return transformation matrix if True

    Returns:
        LLL-reduced matrix and optionally the transformation matrix
    """
    try:
        from flint import fmpz_mat

        B = fmpz_mat(matrix)
        return B.lll(transform=transform)
    except ImportError:
        from sage.all import Matrix

        B = Matrix(matrix)
        return B.LLL(transformation=transform)


def sda(x: list[int], rho: int) -> int | None:
    """
    Solve ACD problem using Simultaneous Diophantine Approximation from
    [Algorithms for the Approximate Common Divisor Problem](https://eprint.iacr.org/2016/215.pdf)

    Args:
        x (list[int]): an array of known x_i = pq_i + r_i
        rho (int): the log2 bound of r_i, i.e. |r_i| < 2 ** rho

    Returns:
        the recovered p, or None for failure
    """

    # Simultaneous Diophantine approximation approach (SDA)

    # step 1:
    # create matrix
    # 2^{rho+1},  x_2,  x_3, ...,  x_t
    #         0, -x_1, ...
    #         0,    0, -x_1, ...
    #         ...
    #         0,    0,       ..., -x_1
    t = len(x)
    matrix = [[0] * t for _ in range(t)]
    matrix[0][0] = 2 ** (rho + 1)
    for i in range(t - 1):
        matrix[0][i + 1] = x[i + 1]
        matrix[i + 1][i + 1] = -x[0]

    # step 2:
    # use lll reduction
    # reduced vector: (q_12^{rho+1}, q_1x_2-q_2x_1, ..., q_1x_t-q_tx_1)
    reduced = matrix_lll(matrix)

    # step 3:
    # recover q_1 from first entry of short vector
    q_1 = reduced[0, 0] // (2 ** (rho + 1))

    # step 4:
    # recover p
    # x_1 = pq_1 + r_1
    # so r_1 = x_1 mod q_1
    # p = (x_1 - r_1) / q_1
    r_1 = x[0] % q_1
    p = abs((x[0] - r_1) // q_1)
    return p


# It may fail sometimes
p = getPrime(512)
rho = 50
x = [random.randrange(0, p) * p + random.randrange(0, 2**rho) for i in range(5)]
res = sda(x, rho)
print(f"Got result:", res != None)
print(f"Result correct:", res == p)
```

## Orthogonal based approach (OL)

Create a lattice according to the paper, and for the $t-1$ short vectors in the lattice, $v_0 = \Sigma u_i r_i$ and $0 = \Sigma u_iq_i$, where $v_0$ is the first entry of the short vector, and $u_i$ are the coefficient of each basis vector. So we got $t-1$ vectors that are orthogonal to the vector of $(q_0, q_1, \cdots, q_t)$. We can compute the $q_i$ by finding the kernel of the vector subspace spanned by $u_i$ vectors. Then, we can recover $q$ in a similar way as previous.

```python
from Crypto.Util.number import getPrime
import random


def matrix_lll(matrix: list[list[int]], transform: bool = False):
    """
    Compute LLL reduction on the given matrix.

    Args:
        matrix (list[list[int]]): the row-major two-dimensional integer matrix
        transform (bool): return transformation matrix if True

    Returns:
        LLL-reduced matrix and optionally the transformation matrix
    """
    try:
        from flint import fmpz_mat

        B = fmpz_mat(matrix)
        return B.lll(transform=transform)
    except ImportError:
        from sage.all import Matrix

        B = Matrix(matrix)
        return B.LLL(transformation=transform)


def find_nullspace_basis(matrix):
    """
    Find the basis of the one-dimensional null space of the space spanend by all vectors except for the last one.

    Args:
        matrix: the input matrix

    Returns:
        the integer basis of the null space
    """
    try:
        from flint import fmpz_mat

        q, nullity = fmpz_mat(matrix.tolist()[:-1]).nullspace()
        assert nullity == 1  # null space should have only one dimension
        return [q[0, i] for i in range(q.ncols())]
    except ImportError:
        q = matrix[:-1][:].right_kernel()
        assert len(q.basis()) == 1  # null space should have only one dimension
        return q.basis()[0]


def ol(x: list[int], rho: int) -> int:
    """
    Solve ACD problem using Orthogonal based approach from
    [Algorithms for the Approximate Common Divisor Problem](https://eprint.iacr.org/2016/215.pdf)

    Args:
        x (list[int]): an array of known x_i = pq_i + r_i
        rho (int): the log2 bound of r_i, i.e. |r_i| < 2 ** rho

    Returns:
        the recovered p
    """

    # step 1:
    # create matrix
    # R = 2^rho
    # x_1, R, 0, ..., 0
    # x_2, 0, R, ..., 0
    # ...
    # x_t, 0, 0, ..., R
    R = 2**rho
    t = len(x)
    matrix = [[0] * (t + 1) for _ in range(t)]
    for i in range(t):
        matrix[i][0] = x[i]
        matrix[i][i + 1] = R

    # step 2:
    # lll reduction
    # transform coefficients for each short vector: (u_1, u_2, ..., u_t)
    # are stored in rows of U
    # U * matrix == LLL-reduced matrix
    _, U = matrix_lll(matrix, True)

    # for short enough vector
    # v_0 = sum(u_i * r_i),
    # 0 = sum(u_i * q_i)
    # so u vector is orthogonal to q vector

    # step 3:
    # find kernel (null space) of the space,
    # spanned by t-1 u vectors from U
    q_1 = abs(find_nullspace_basis(U)[0])

    # step 4:
    # recover p
    # r_1 = x_1 mod q_1
    r_1 = x[0] % q_1
    # p = (x_1 - r_1) // q_1
    p = (x[0] - r_1) // q_1

    return p


# It may fail sometimes
p = getPrime(512)
rho = 50
x = [random.randrange(0, p) * p + random.randrange(0, 2**rho) for i in range(5)]
res = ol(x, rho)
print(f"Got result:", res != None)
print(f"Result correct:", res == p)
```
