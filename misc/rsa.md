# Solving RSA private key

Table of contents:

* TOC
{:toc}

## Small N

If N is small, we can factor it directly. We can solve RSA200 in ~2s:

```python
from sage.all import *
from Crypto.Util.number import *

p = getPrime(100)
q = getPrime(100)
n = p * q
print(p, q)
print(Integer(n).factor())
```

## Small d

Use Wiener's attack for small d.

```python
from sage.all import *
from Crypto.Util.number import *
import random

p = getPrime(1024)
q = getPrime(1024)
n = p * q
d = random.randrange(1, 2**500)

while True:
    try:
        e = pow(d, -1, (p - 1) * (q - 1))
        break
    except:
        d = random.randrange(1, 2**500)
        continue


# https://cryptohack.gitbook.io/cryptobook/untitled/low-private-component-attacks/wieners-attack
def wiener(e, n):
    # Ensure we are using Integer from sage, not int
    e = Integer(e)
    n = Integer(n)
    # Convert e/n into a continued fraction
    cf = continued_fraction(e / n)
    convergents = cf.convergents()
    for kd in convergents:
        k = kd.numerator()
        d = kd.denominator()
        # Check if k and d meet the requirements
        if k == 0 or d % 2 == 0 or e * d % k != 1:
            continue
        phi = (e * d - 1) / k
        # Create the polynomial
        x = PolynomialRing(RationalField(), "x").gen()
        f = x**2 - (n - phi + 1) * x + n
        roots = f.roots()
        # Check if polynomial as two roots
        if len(roots) != 2:
            continue
        # Check if roots of the polynomial are p and q
        p, q = int(roots[0][0]), int(roots[1][0])
        if p * q == n:
            return d
    return None


assert wiener(e, n) == d
print("Success")
```

CTF challenges:

- [K17 CTF 2025 worsehelp](../2025-09-19-k17-ctf-2025/worsehelp.md)

## Known n and p-q

Since $n = pq$, so $n=p(p-(p-q))$, $p^2-(p-q)p-n=0$, solve the quadratic equation to find $p$.

```python
import math
from Crypto.Util.number import *

p = getPrime(1024)
q = getPrime(1024)
n = p * q

diff = p - q


def attack(n, diff):
    # n = p * (p - diff)
    # p ** 2 - diff * p - n = 0
    # p = (diff + sqrt(diff ** 2 + 4 * n)) / 2
    p = (diff + math.isqrt(diff**2 + 4 * n)) // 2
    q = n // p
    assert n == p * q
    return p


assert attack(n, diff) == p
print("Success")
```

CTF challenges:

- [Hack The Boo CTF 2025 Leaking for Answers](../2025-10-24-hack-the-boo-ctf-2025/leaking-for-answers.md)


## Known n, small e, pow(phi, -1, n) * d % n

Solve:

$ed = 1 \pmod \phi$

So there exists integer $k$:

$ed = k\phi + 1$

Since $d < \phi$, so $k < e$.

Multiply $\phi^{-1}$ on both sides modulo $n$:

$\phi^{-1}de = k + \phi^{-1} \pmod n$

Left side is known. $k < e$ which is small and can be enumerated. We can recover $\phi^{-1}$ and solve $p$ for each $k$.

```python
import math
import tqdm
from Crypto.Util.number import *

p = getPrime(1024)
q = getPrime(1024)
e = 0x10001
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
n = p * q

known = pow(phi, -1, n) * d % n


def attack(n, e, known):
    # find k
    for k in tqdm.trange(100000):
        # e*d = 1 mod phi
        # e*d = phi*k+1
        # pow(phi, -1, n) * d * e = k + pow(phi, -1, n)
        phi_inv = known * e % n - k
        phi = pow(phi_inv, -1, n)
        # good phi?
        # phi = p * q - p - q + 1
        # n = p * q
        # p + q = n + 1 - phi
        p_plus_q = n + 1 - phi
        # p * (p_plus_q - p) = n
        # - p ** 2 + p_plus_q * p - n = 0
        p = (-p_plus_q - math.isqrt(p_plus_q**2 - 4 * n)) // -2
        q = n // p
        if p * q == n and (p - 1) * (q - 1) == phi:
            # found
            return p
    return None


assert attack(n, e, known) == p
print("Success")
```

CTF challenges:

- [Hack The Boo CTF 2025 Leaking for Answers](../2025-10-24-hack-the-boo-ctf-2025/leaking-for-answers.md)


## Known n, e, d

Reference: <https://stackoverflow.com/questions/2921406/calculate-primes-p-and-q-from-private-exponent-d-public-exponent-e-and-the> and <https://gist.github.com/ddddavidee/b34c2b67757a54ce75cb>

Implement the algorithm specified in the link above.

```python
import random
from Crypto.Util.number import *
import math

p = getPrime(1024)
q = getPrime(1024)
e = 0x10001
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
n = p * q

# https://stackoverflow.com/questions/2921406/calculate-primes-p-and-q-from-private-exponent-d-public-exponent-e-and-the
def attack(n, e, d):
    # 1. Let k = de – 1. If k is odd, then go to Step 4.
    k = d * e - 1
    if k % 2 == 1:
        # 4. Output “prime factors not found,” and exit without further processing.
        return None

    # 2. Write k as k=2^{t}r, where r is the largest odd integer dividing k, and t >= 1.
    r = k
    t = 0
    while r % 2 == 0:
        r = r // 2
        t = t + 1
    assert k == 2**t * r

    # 3. For i = 1 to 100 do:
    for i in range(100):
        # a. Generate a random integer g in the range [0, n-1].
        g = random.randrange(0, n)
        # b. Let y=g^r mod n.
        y = pow(g, r, n)
        # c. If y = 1 or y = n – 1, then go to Step g
        if y == 1 or y == n - 1:
            # g. Continue.
            continue
        # d. For j = 1 to t – 1 do:
        for j in range(1, t):
            # i. Let x = y^2 mod n
            x = pow(y, 2, n)
            # ii. If x = 1, go to Step 5
            if x == 1:
                # 5. Let p = GCD(y-1, n) and let q = n/p
                p = math.gcd(y - 1, n)
                q = n // p
                assert p * q == n
                return p
            # iii. If x = n - 1, go to Step g.
            elif x == n - 1:
                break
            # iv. Let y = x.
            y = x
        else:
            # e. Let x = y^2 mod n
            x = pow(y, 2, n)
            # f. If x = 1, go to Step 5
            if x == 1:
                # 5. Let p = GCD(y-1, n) and let q = n/p
                p = math.gcd(y - 1, n)
                q = n // p
                assert p * q == n
                return p


res = attack(n, e, d)
assert res == p or res == q
print("Success")
```

CTF challenges:

- [Hack The Boo CTF 2025 Leaking for Answers](../2025-10-24-hack-the-boo-ctf-2025/leaking-for-answers.md)

### Small e

Alternatively, if e is small, then:

$ed = k\phi + 1$ where $k$ is an integer smaller than $e$.

We can enumerate $k$ to compute $\phi$:

```python
import tqdm
from Crypto.Util.number import *
import math

p = getPrime(1024)
q = getPrime(1024)
e = 0x10001
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
n = p * q


def attack(n, e, d):
    # find k
    for k in tqdm.trange(1, 100000):
        # e*d = 1 mod phi
        # e*d = phi*k+1
        phi = (e * d - 1) // k
        # good phi?
        # phi = p * q - p - q + 1
        # n = p * q
        # p + q = n + 1 - phi
        p_plus_q = n + 1 - phi
        # p * (p_plus_q - p) = n
        # - p ** 2 + p_plus_q * p - n = 0
        p = (-p_plus_q - math.isqrt(p_plus_q**2 - 4 * n)) // -2
        q = n // p
        if p * q == n and (p - 1) * (q - 1) == phi:
            # found
            return p
    return None


res = attack(n, e, d)
assert res == p or res == q
print("Success")
```

## Known n, pow(p, -1, q), pow(q, -1, p)

Solve:

$A=\mathrm{pow}(p, -1, q)$, $B=\mathrm{pow}(q, -1, p)$, so

$Ap = 1 \pmod q$, $Bq = 1 \pmod p$, then $Ap + Bq = 1 + 0 = 1 \pmod q$, and $Ap + Bq = 0 + 1 = 1 \pmod p$, by Chinese Remainder Theorem, $Ap + Bq = 1 \pmod n$.

Because $A<q$ and $B<p$ so $Ap+Bq < pq + pq = 2n$, so $Ap + Bq = n+1$. Multiply by $p$: $Ap^2+Bn = (n+1)p$. Solve $p$ from $Ap^2-(n+1)p+Bn = 0$.

```python
from Crypto.Util.number import *
import math

p = getPrime(1024)
q = getPrime(1024)
n = p * q
A = pow(p, -1, q)
B = pow(q, -1, p)


def attack(n, A, B):
    p = ((n + 1) + math.isqrt((n + 1) ** 2 - 4 * A * B * n)) // (2 * A)
    q = n // p
    assert n == p * q
    return p


res = attack(n, A, B)
assert res == p or res == q
print("Success")
```

CTF challenges:

- [Hack The Boo CTF 2025 Leaking for Answers](../2025-10-24-hack-the-boo-ctf-2025/leaking-for-answers.md)

## Known n, MSB bits of p

If we know n, and MSB bits of p: `p // (2 ** shift)`. There exists some small integer $x$ where $\lfloor p / 2^{\mathrm{shift}} \rfloor 2 ^ {\mathrm{shift}} + x = 0 \pmod p$

We can recover $p$ using Coppersmith's attack: find small roots of the equation $\lfloor p / 2^{\mathrm{shift}} \rfloor 2 ^ {\mathrm{shift}} + x = 0 \pmod N$ modulo some factor $b$ of $N$, which should be $p$ here.

Note the parameter selection (beta and epsilon) on [sage's implementation of small_roots](https://doc.sagemath.org/html/en/reference/polynomial_rings/sage/rings/polynomial/polynomial_modn_dense_ntl.html#sage.rings.polynomial.polynomial_modn_dense_ntl.small_roots):

1. $b = p \ge N^{\beta}$, so $N^{\beta}$ should be less than $p$. We don't know $p$, but since $p$ and $q$ are of the same bit length, $\beta$ should be about 0.5, often smaller to ensure the inequality
2. $\epsilon$ determines the range of $x$ found, smaller $\epsilon$ means larger $x$ allowed, but takes more time; lower $\epsilon$ until you find a solution in a reasonable time; for example, in the following example, $\epsilon=0.05$ gives no solution, but $\epsilon=0.04$ solves in 0.5s, $\epsilon=0.01$ solves in 7s.

```python
from sage.all import *
from Crypto.Util.number import *

p = getPrime(512)
q = getPrime(512)
n = p * q
shift = 233
known = p // (2**shift)


def attack(n, known, shift):
    # https://latticehacks.cr.yp.to/rsa.html
    # modulo n
    R = Zmod(n)["x"]
    x = R.gens()[0]

    # find small root of equation a + x = 0 (mod p)
    # x = the missing LSB bits
    # Coppersmith attack
    f = known * (Integer(1) << shift) + x

    # small root bound: |x| < 2^shift
    # returns small roots of this polynomial modulo some factor b of N
    # where b >= N^{beta}, which is p
    # we don't know p, but it should be around sqrt(n)
    for beta in range(40, 50):
        # test beta from 0.4 to 0.5
        beta = beta / 100
        # smaller epsilon finds larger root, but takes longer time
        roots = f.small_roots(X=1 << shift, beta=beta, epsilon=0.02)
        if len(roots) >= 1:
            break

    # roots[0] is x, compute p
    # may fail in some cases
    p = int(roots[0]) + known * (2**shift)
    q = n // p
    assert p * q == n
    return p


res = attack(n, known, shift)
assert res == p or res == q
print("Success")
```

## Known n, close p and q

If $p$ and $q$ are very close (e.g. $q$ is the smallest prime larger than $p$), the diff can be very small. We can enumerate the diff and solve $p$ and $q$.
