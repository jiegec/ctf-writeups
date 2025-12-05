# Recover Linear Congruential Generator (LCG) Parameters

Linear Congruential Generators (LCGs) generate pseudorandom numbers using the recurrence:
$x_{i+1} = (a \cdot x_i + b) \bmod p$

This document provides techniques for recovering LCG parameters (`a`, `b`, `p`) and seeds from various types of outputs, including truncated outputs where only partial bits are known.

**Table of contents:**

* TOC
{:toc}

## Recover Full LCG Parameters from Complete Outputs

When we have complete outputs from an LCG, we can recover all parameters using algebraic techniques.

**Attack principle:** Given consecutive outputs $x_0, x_1, x_2, \dots$, we can:

1. Cancel out $b$ by computing differences $y_i = x_{i+1} - x_i$, then $y_i \bmod p = ((ax_i + b) - (ax_{i-1} + b)) \bmod p = (a(x_i - x_{i-1})) \bmod p$, so $y_{i} = ay_{i-1} \pmod p$
2. Cancel out $a$ by computing $z_i = y_{i+2}y_i - y_{i+1}^2$ so $z_i \bmod p = (a^2y_i^2 - (ay_i)^2) \bmod p = 0$
3. Recover $p$ as $\gcd(z_i)$
4. Recover $a$ from $y_i = a \cdot y_{i-1} \pmod p$
5. Recover $b$ from $x_{i+1} = a \cdot x_i + b \pmod p$

**Reference:** <https://security.stackexchange.com/questions/4268/cracking-a-linear-congruential-generator>

**Example code:**

```python
# recover LCG
# given an array of x_i
# x_{i+1} = (ax_i + b) \bmod p

from pwn import *
from Crypto.Util.number import *

p = getPrime(256)
state = random.randrange(1, p)
x0 = state
a = random.randrange(1, p)
b = random.randrange(1, p)
x = []
for i in range(100):
    state = (a * state + b) % p
    x.append(state)

# recover p
# compute y_i = x_{i+1} - x_i
y = []
for i in range(len(x) - 1):
    y.append(x[i + 1] - x[i])

# compute z_i = y_{i+2}y_i - y_{i+1}^2
z = []
for i in range(len(y) - 2):
    z.append(y[i + 2] * y[i] - y[i + 1] ** 2)

# compute gcd, we found p
assert p == math.gcd(*z)
print("p is found")

# compute a from y_iy_{i-1}^{-1} \bmod p
assert a == (y[1] * pow(y[0], -1, p)) % p
print("a is found")

# compute b from (x_{i+1} - ax_i) \bmod p
assert b == (x[1] - a * x[0]) % p
print("b is found")

# find initial state x_0 = (x_1 - b) * a^{-1} \bmod p
assert x0 == (x[0] - b) * pow(a, -1, p) % p
print("initial state is found")
```

## Recover truncated LCG

Reference: <https://github.com/ajuelosemmanuel/Truncated_LCG_Seed_Recovery/tree/main>

Truncated LCG is where you can only know part of the generated number, e.g. the MSB or LSB bits.

### Variant 1: p and MSB bits are known, b = 0

The first variant is, p and MSB bits are known and b = 0, so:

$x_{i+1} = ax_i \bmod p$, so $x_i = x_0 a^i \bmod p$

We only know the MSB bits of $x_i$, e.g. we only have $y_i = \lfloor x_i / 256 \rfloor$, we need to recover $a$. We know that $256y_i$ is close to $x_i$.

We need to convert it to a closest vector problem, consider the following vectors:

$v_1 = (1, a, a^2, a^3, \cdots, a^{n-1})$

$v_2 = (0, p, 0, 0, \cdots, 0)$

$v_3 = (0, 0, p, 0, \cdots, 0)$

...

$v_n = (0, p, 0, 0, \cdots, p)$

If there is a linear combination of these vectors using integer coefficients:

$w = c_1v_1 + c_2v_2 + \cdots c_nv_n = (c_1, c_1a+c_2p, \cdots, c_na^{n-1} + c_np)$

If $w$ is very close to $y = (256y_0, 256y_1, \cdots, 256y_{n-1})$, then we are finding a solution that $c_1$ is close to $256y_0=256\lfloor x_0/256 \rfloor$, $c_1a+c_2p$ is close to $256 \lfloor (x_0a \bmod p)/256 \rfloor$. The modulo $p$ is implemented by adding $c_ip$ to $c_ia^{i-1}$. Since only the LSB bits are removed, so the solution should corresponds to the seed that minimizes all the differences. Given enough values, we can recover the seed $x_0$ by $c_1$.

Code:

```python
# recover seed from a truncated LCG without b
# we only know the MSB of generated values
# given a, p, an array of (seed * a ** i) % p // (2 ** shift)
# recover seed

# the idea is learned from:
# https://github.com/ajuelosemmanuel/Truncated_LCG_Seed_Recovery/blob/main/attack_exemple_lsb.py
# create matrix
# 1 a a^2 a^3 ... a^{size-1}
# 0 p   0   0 ...          0
# 0 0   p   0 ...          0
# ...
# 0 0   0   0 ...          p
# the linear combination of these row vectors become:
# seed seed*a-p*k_1 seed*a^2-p*k_2 ... seed*a^{size-1}-p*k_{size-1}
# we already know a vector of (seed * a ** i) % p // (2 ** shift)
# so the linear combination of the row vectors are close to the known vector,
# because modulo p is mapped to seed*a^i-p*k_i
# use CVP to find the combination, so seed is known

from pwn import *
from fpylll import *
from Crypto.Util.number import *

# compute (seed * a ** i) % p // (2 ** shift)
p = getPrime(128)
seed = random.randrange(1, p)
a = random.randrange(1, p)
shift = 8
all_nums = [((seed * pow(a, i, p)) % p) // (2**shift) for i in range(5)]


def attack(a: int, p: int, shift: int, Ys: list):
    # the problem is:
    # given (seed * a^i) % p // (2 ** shift)
    # recover seed

    # compute the value before division
    I = 2**shift
    y = [(el * I) % p for el in Ys]

    # construct row vectors as a matrix
    size = len(Ys)
    matrix = [[0] * size for _ in range(size)]
    for i in range(size):
        matrix[0][i] = pow(a, i, p)
    for i, j in zip(range(1, size), range(1, size)):
        if i == j:
            matrix[i][j] = p

    # find closest vector to y
    L = IntegerMatrix.from_matrix(matrix)
    reduced = LLL.reduction(L)
    Xi_I = CVP.closest_vector(reduced, y, method="fast")

    # seed is the first element
    probable_seed = Xi_I[0] % p

    # recover the generated values
    probable_ys = [
        ((probable_seed * pow(a, i, p)) % p) // (2**shift) for i in range(0, len(Ys))
    ]

    print("Seed recovery success:", probable_ys == Ys)
    return probable_seed


# recover seed
assert attack(a, p, shift, all_nums) == seed
```

### Variant 1b: p and MSB bits are known, b != 0

The variant 1b no longer enforces $b = 0$. On top of the variant 1, an extra step is required to cancel out $b$:

$x_{i+1} = (ax_i + b) \bmod p$

Set $z_i = (x_i + b(a-1)^{-1}) \bmod p$, so

$z_{i+1} = (x_{i+1} + b(a-1)^{-1}) \bmod p = (ax_i + b + b(a-1)^{-1}) \bmod p = (ax_i + b(a-1)(a-1)^{-1} + b(a-1)^{-1}) \bmod p = (ax_i + ab(a-1)^{-1} \bmod p = (a(x_i + b(a-1)^{-1})) \bmod p = az_i \bmod p$

Now, we can apply the solution of variant 1 to $z_i$, and recover $x_i$ by subtracting $b(a-1)^{-1}$ from $z_i$:

```python
# recover seed from a truncated LCG without b
# we only know the MSB of generated values
# given a, b, p, an array of truncated x_i where
# x_{i+1} = (ax_i + b) \bmod p
# recover x_0

# the idea is learned from:
# https://github.com/ajuelosemmanuel/Truncated_LCG_Seed_Recovery/blob/main/attack_exemple_lsb.py
# create matrix
# 1 a a^2 a^3 ... a^{size-1}
# 0 p   0   0 ...          0
# 0 0   p   0 ...          0
# ...
# 0 0   0   0 ...          p
# the linear combination of these row vectors become:
# seed seed*a-p*k_1 seed*a^2-p*k_2 ... seed*a^{size-1}-p*k_{size-1}
# we already know a vector of (seed * a ** i) % p // (2 ** shift)
# after we cancel out b
# so the linear combination of the row vectors are close to the known vector,
# because modulo p is mapped to seed*a^i-p*k_i
# use CVP to find the combination, so seed is known

from pwn import *
from fpylll import *
from Crypto.Util.number import *

# compute truncated values
p = getPrime(8)
seed = random.randrange(1, p)
a = random.randrange(1, p)
b = random.randrange(1, p)
shift = 1
all_nums = []
orig = []
x = seed
for i in range(10):
    orig.append(x)
    all_nums.append(x // (2**shift))
    x = (a * x + b) % p


def attack(a: int, b: int, p: int, shift: int, Ys: list):
    # the problem is:
    # x_{i+1} = (ax_i + b) \bmod p
    # recover x_0

    # compute the value before division
    I = 2**shift
    y = [(el * I) % p for el in Ys]

    # cancel b by adding b(a-1)^{-1}
    # x_{i+1} = (ax_i + b) \bmod p
    # z_i = x_i + b(a-1)^{-1}
    # z_{i+1} = (x_{i+1} + b(a-1)^{-1}) \bmod p
    #         = (ax_i + b + b(a-1)^{-1}) \bmod p
    #         = (ax_i + ab(a-1)^{-1}) \bmod p
    #         = (az_i) \bmod p
    z = [(y[i] + b * pow(a - 1, -1, p)) % p for i in range(len(y))]

    # construct row vectors as a matrix
    size = len(z)
    matrix = [[0] * size for _ in range(size)]
    for i in range(size):
        matrix[0][i] = pow(a, i, p)
    for i, j in zip(range(1, size), range(1, size)):
        if i == j:
            matrix[i][j] = p

    # find closest vector to y
    L = IntegerMatrix.from_matrix(matrix)
    reduced = LLL.reduction(L)
    Xi_I = CVP.closest_vector(reduced, z, method="fast")

    # seed is the first element, drop the extra coefficient
    probable_seed = (Xi_I[0] - b * pow(a - 1, -1, p)) % p

    # recover the generated values
    probable_ys = []
    x = probable_seed
    for i in range(len(Ys)):
        probable_ys.append(x // (2 * shift))
        x = (a * x + b) % p

    print("Seed recovery success:", probable_ys == Ys)
    return probable_seed


# recover seed
assert attack(a, b, p, shift, all_nums) == seed
```

### Variant 2: p and LSB bits are known, b == 0

Now, we only know the LSB bits, e.g. $y_i = x_i \bmod 256$. To convert into variant 1:

$x_i = (256z_i + y_i) \bmod p$

$256^{-1}x_i \bmod p = (z_i + 256^{-1}y_i) \bmod p$

Now, $z_i$ is the small one. We have a approximation of $256^{-1}x_i$ by $256^{-1}y_i$. So, we can solve the problem in the same way as variant 1.

Code:

```python
# recover seed from a truncated LCG without b
# we only know the LSB of generated values
# given a, p, an array of (seed * a ** i) % p % (2 ** shift)
# recover seed

# convert the problem to where we know the MSB
# y_i is the LSB, z_i is the MSB
# x_i = (2 ** shift) * z_i + y_i
# x_i * (2 ** shift)^{-1} = z_i + y_i * (2 ** shift)^{-1}
# now y_i * (2 ** shift)^{-1} approximately equals to x_i * (2 ** shift)^{-1} modulo p

from pwn import *
from fpylll import *
from Crypto.Util.number import *

# compute (seed * a ** i) % p % (2 ** shift)
p = getPrime(128)
seed = random.randrange(1, p)
a = random.randrange(1, p)
shift = 8
all_nums = [((seed * pow(a, i, p)) % p) % (2**shift) for i in range(20)]


def attack(a: int, p: int, shift: int, Ys: list):
    # the problem is:
    # given (seed * a^i) % p % (2 ** shift)
    # recover seed

    # convert to
    # given (seed * a^i) % p // (2 ** shift)

    # compute the value before division for MSB
    I = pow(2**shift, -1, p)
    y = [(el * I) % p for el in Ys]

    # construct row vectors as a matrix
    size = len(Ys)
    matrix = [[0] * size for _ in range(size)]
    for i in range(size):
        matrix[0][i] = pow(a, i, p)
    for i, j in zip(range(1, size), range(1, size)):
        if i == j:
            matrix[i][j] = p

    # find closest vector to y
    L = IntegerMatrix.from_matrix(matrix)
    reduced = LLL.reduction(L)
    Xi_I = CVP.closest_vector(reduced, y, method="fast")

    # seed is the first element, but we need to multiple 2**shift back
    probable_seed = Xi_I[0] * (2**shift) % p

    # recover the generated values
    probable_ys = [
        ((probable_seed * pow(a, i, p)) % p) % (2**shift) for i in range(0, len(Ys))
    ]

    print("Seed recovery success:", probable_ys == Ys)
    return probable_seed


# recover seed
assert attack(a, p, shift, all_nums) == seed
```

### Variant 2b: p and LSB bits are known, b != 0

To lift the limitation of $b$, cancel out $b$ in the same way as in Variant 1b.

$x_{i+1} = (ax_i + b) \bmod p$

$y_i = x_i \bmod 256$

$x_i = (256z_i + y_i) \bmod p$

$256^{-1}x_i \bmod p = (z_i + 256^{-1}y_i) \bmod p$

$z_i = 256^{-1}(x_i + b(a-1)^{-1})$

$z_{i+1} = az_i \bmod p$

### Solution

Here is the solution for all variants:

```python
# recover seed from a truncated LCG without b
# we only know the MSB/LSB of generated values
# given a, b, p, an array of truncated x_i where
# x_{i+1} = (ax_i + b) \bmod p
# recover x_0

# the idea is learned from:
# https://github.com/ajuelosemmanuel/Truncated_LCG_Seed_Recovery/blob/main/attack_exemple_lsb.py
# create matrix
# 1 a a^2 a^3 ... a^{size-1}
# 0 p   0   0 ...          0
# 0 0   p   0 ...          0
# ...
# 0 0   0   0 ...          p
# the linear combination of these row vectors become:
# seed seed*a-p*k_1 seed*a^2-p*k_2 ... seed*a^{size-1}-p*k_{size-1}
# we already know a vector that approximate (seed * a ** i) % p
# so the linear combination of the row vectors are close to the known vector,
# because modulo p is mapped to seed*a^i-p*k_i
# use CVP to find the combination, so seed is known

from pwn import *
from fpylll import *
from Crypto.Util.number import *


def attack(a: int, b: int, p: int, lsb: bool, shift: int, Ys: list):
    # the problem is:
    # x_{i+1} = (ax_i + b) \bmod p
    # recover x_0

    # compute the value before division for approximation
    if lsb:
        I = pow(2**shift, -1, p)
    else:
        I = 2**shift
    y = [(el * I) % p for el in Ys]

    # cancel b by adding b(a-1)^{-1}
    # x_{i+1} = (ax_i + b) \bmod p
    # z_i = x_i + b(a-1)^{-1}
    # z_{i+1} = (x_{i+1} + b(a-1)^{-1}) \bmod p
    #         = (ax_i + b + b(a-1)^{-1}) \bmod p
    #         = (ax_i + ab(a-1)^{-1}) \bmod p
    #         = (az_i) \bmod p
    if lsb:
        z = [
            (y[i] + b * pow(a - 1, -1, p) * pow(2**shift, -1, p)) % p
            for i in range(len(y))
        ]
    else:
        z = [(y[i] + b * pow(a - 1, -1, p)) % p for i in range(len(y))]

    # construct row vectors as a matrix
    size = len(z)
    matrix = [[0] * size for _ in range(size)]
    for i in range(size):
        matrix[0][i] = pow(a, i, p)
    for i, j in zip(range(1, size), range(1, size)):
        if i == j:
            matrix[i][j] = p

    # find closest vector to y
    L = IntegerMatrix.from_matrix(matrix)
    reduced = LLL.reduction(L)
    Xi_I = CVP.closest_vector(reduced, z, method="fast")

    # seed is the first element, drop the extra coefficient
    probable_seed = Xi_I[0] % p
    if lsb:
        probable_seed = (probable_seed * (2**shift)) % p
    probable_seed = (probable_seed - b * pow(a - 1, -1, p)) % p

    # recover the generated values
    probable_ys = []
    x = probable_seed
    for i in range(len(Ys)):
        if lsb:
            probable_ys.append(x % (2**shift))
        else:
            probable_ys.append(x // (2**shift))
        x = (a * x + b) % p

    print("Seed recovery success:", probable_ys == Ys)
    return probable_seed


def test(lsb: bool):
    # compute truncated values
    p = getPrime(8)
    seed = random.randrange(1, p)
    a = random.randrange(1, p)
    b = random.randrange(1, p)
    if lsb:
        # lowest 6 bits
        shift = 6
    else:
        # highest 6 bits
        shift = 2
    all_nums = []
    orig = []
    x = seed
    for i in range(20):
        orig.append(x)
        if lsb:
            # LSB
            all_nums.append(x % (2**shift))
        else:
            # MSB
            all_nums.append(x // (2**shift))
        x = (a * x + b) % p

    # recover seed
    assert attack(a, b, p, lsb, shift, all_nums) == seed


test(False)
test(True)
```

## CTF challenges

- [Qiangwang Mimic Quals 2025 FMS](../2025-10-25-qiangwang-nitai-quals-2025/FMS.md)
