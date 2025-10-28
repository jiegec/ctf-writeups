# Leaking for Answers

We need to solve some RSA from given numbers.

First question: given $n$ and $p-q$, solve $p$ and $q$.

Since $n = pq$, so $n=p(p-(p-q))$, $p^2-(p-q)p-n=0$, solve the quadratic equation to find $p$.

Second equation: given $n$, $e$, $\phi^{-1}d \bmod n$.

Since $ed = 1 \bmod \phi$, so there is a $k$ where $ed = \phi k+1$, so $\phi^{-1}de = k + \phi^{-1} \pmod n$.

The $k$ is small, because $e$ is not large. So we can enumerate $k$ until we find $\phi$. Given $\phi$, we know that $\phi = pq - p - q + 1$ and $n = pq$, so $p + q = n + 1 - \phi$, $p (p + q - p) = n$, $-p^2 + (p + 1) * p - n = 0$, solve the quadratic equation to find $p$.

Third equation, given $n$, $e$ and $d$, use [existing code](gist.github.com/ddddavidee/b34c2b67757a54ce75cb) to solve.

Fourth question, given $n$, `pow(p, -q, q)` and `pow(q, -p, p)`. By Fermat's little theorm, `pow(p, -q, q)` equals to inverse of $p$ modulo $q$. Let `A=pow(p, -q, q)`, `B=pow(q, -p, p)`, so $Ap = 1 \pmod q$ and $Bq = 1 \pmod p$, then $Ap+Bq = 1 \pmod p$ and $Ap+Bq = 1 \pmod q$, $Ap+Bq = 1 \pmod n$, since $A<q$ and $B<q$, so $Ap+Bq=n+1$ is the only solution. Then, we can solve $p$ from the quadratic equation $A p^2 - (n+1)p + Bn = 0$.

Attack script:

```python
from pwn import *
import math
import tqdm

context(log_level="debug")

r = remote("46.101.163.234", 32080)

# first question: known n and p-q
r.recvuntil(b"n = ")
n = int(r.recvline().decode().strip())
print("n", n)
r.recvuntil(b"p-q = ")
diff = int(r.recvline().decode().strip())
print("p-q", diff)

# n = p * (p - diff)
# p ** 2 - diff * p - n = 0
# p = (diff + sqrt(diff ** 2 + 4 * n)) / 2
p = (diff + math.isqrt(diff**2 + 4 * n)) // 2
q = n // p
assert n == p * q
r.sendline(f"{p},{q}".encode())

# second question: known n, e, pow(phi, -1, n) * d % n
# e*d = 1 mod phi
# e*d = phi*k+1
# pow(phi, -1, n) * d * e = k + pow(phi, -1, n)
r.recvuntil(b"n = ")
n = int(r.recvline().decode().strip())
print("n", n)

r.recvuntil(b"e = ")
e = int(r.recvline().decode().strip())
print("e", e)

r.recvuntil(b"pow(phi, -1, n) * d % n = ")
result = int(r.recvline().decode().strip())
print("pow(phi, -1, n) * d % n", result)

# find k
for k in tqdm.trange(100000):
    phi_inv = result * e % n - k
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
        r.sendline(f"{p},{q}".encode())
        break

# third question: known n, e, d
r.recvuntil(b"n = ")
n = int(r.recvline().decode().strip())
print("n", n)

r.recvuntil(b"e = ")
e = int(r.recvline().decode().strip())
print("e", e)

r.recvuntil(b"d = ")
d = int(r.recvline().decode().strip())
print("d", d)

# https://gist.github.com/ddddavidee/b34c2b67757a54ce75cb
from math import gcd  # for gcd function (or easily implementable to avoid import)
import random  # for random elements drawing in RecoverPrimeFactors


def failFunction():
    print("Prime factors not found")


def outputPrimes(a, n):
    p = gcd(a, n)
    q = int(n // p)
    if p > q:
        p, q = q, p
    print("Found factors p and q")
    print("p = {0}".format(str(p)))
    print("q = {0}".format(str(q)))
    return p, q


def RecoverPrimeFactors(n, e, d):
    """The following algorithm recovers the prime factor
    s of a modulus, given the public and private
    exponents.
    Function call: RecoverPrimeFactors(n, e, d)
    Input: 	n: modulus
                    e: public exponent
                    d: private exponent
    Output: (p, q): prime factors of modulus"""

    k = d * e - 1
    if k % 2 == 1:
        failFunction()
        return 0, 0
    else:
        t = 0
        r = k
        while r % 2 == 0:
            r = int(r // 2)
            t += 1
        for i in range(1, 101):
            g = random.randint(0, n)  # random g in [0, n-1]
            y = pow(g, r, n)
            if y == 1 or y == n - 1:
                continue
            else:
                for j in range(1, t):  # j \in [1, t-1]
                    x = pow(y, 2, n)
                    if x == 1:
                        p, q = outputPrimes(y - 1, n)
                        return p, q
                    elif x == n - 1:
                        continue
                    y = x
                    x = pow(y, 2, n)
                    if x == 1:
                        p, q = outputPrimes(y - 1, n)
                        return p, q


p, q = RecoverPrimeFactors(n, e, d)
r.sendline(f"{p},{q}".encode())

# fourth question: known n, pow(p, -q, q), pow(q, -p, p)
# pow(p, q, q) = p, pow1 * p = k * q + 1
# pow(q, p, p) = q, pow2 * q = l * p + 1
# (pow1 * p + pow2 * q) mod p = 1
# (pow1 * p + pow2 * q) mod q = 1
# therefore:
# (pow1 * p + pow2 * q) mod n = 1
# pow1 < q, pow2 < p, so
# pow1 * p + pow2 * q = n + 1
# pow1 * p ** 2 + pow2 * n = (n + 1) * p
# pow1 * p ** 2 - (n + 1) * p + pow2 * n = 0
# p = ((n + 1) + sqrt((n + 1) ** 2 - 4 * pow1 * pow2 * n)) / 2 / pow1
r.recvuntil(b"n = ")
n = int(r.recvline().decode().strip())
print("n", n)

r.recvuntil(b"pow(p, -q, q) = ")
pow1 = int(r.recvline().decode().strip())
print("pow(p, -q, q)", pow1)

r.recvuntil(b"pow(q, -p, p) = ")
pow2 = int(r.recvline().decode().strip())
print("pow(q, -p, p)", pow2)
p = ((n + 1) + math.isqrt((n + 1) ** 2 - 4 * pow1 * pow2 * n)) // (2 * pow1)
q = n // p
assert n == p * q
r.sendline(f"{p},{q}".encode())

r.recvall()
```

Flag: `HTB{t0_l34k___0r_n0t___t0_l34k_f0r_4nsw3rs_758dd2da6409e36a5ec63cc933a8bf1f}`.
