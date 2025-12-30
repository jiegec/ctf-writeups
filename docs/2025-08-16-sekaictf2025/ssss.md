# SSSS

```
Cryptography

Shamir SendS the Secret to everyone

Author: Utaha
ncat --ssl ssss.chals.sekai.team 1337
```

Attachment:

```python
#!/usr/bin/python3
import random, os

p = 2 ** 256 - 189
FLAG = os.getenv("FLAG", "SEKAI{}")

def challenge(secret):
        t = int(input())
        assert 20 <= t <= 50, "Number of parties not in range"

        f = gen(t, secret)

        for i in range(t):
                x = int(input())
                assert 0 < x < p, "Bad input"
                print(poly_eval(f, x))

        if int(input()) == secret:
                print(FLAG)
                exit(0)
        else:
                print(":<")

def gen(degree, secret):
        poly = [random.randrange(0, p) for _ in range(degree + 1)]
        index = random.randint(0, degree)

        poly[index] = secret
        return poly

def poly_eval(f, x):
        return sum(c * pow(x, i, p) for i, c in enumerate(f)) % p

if __name__ == "__main__":
        secret = random.randrange(0, p)
        for _ in range(2):
                challenge(secret)
```

The problem is:

1. the attacker can chooose $t$
2. the server generates a polynoimal of order $t$ with $t+1$ random coefficients, one of them is the secret value
3. the attacker can query $t$ points on the polynomial, then validates secret value
4. the whole process is repeated at most twice

Initially, I think it is impossible: we only have $t$ equations, but we have $t+1$ unknown coefficients to solve. Even if we consider both attempts, we have $2t$ equations, but there are $2t+1$ unknown efficients (the secret is shared between two equations). Still not solvable.

I failed to solve it in the competition. After reading <https://github.com/project-sekai-ctf/sekaictf-2025/blob/main/crypto/ssss/solution/solve.sage> the official writeup, the solution is interesting and worth a writeup.

The idea is, reduce one unknown efficient. Our problem is a system of modular equations:

$$
\begin{gather*}
a_0 + a_1x_1 + a_2x_1^2 + \cdots + a_tx_1^t = y_1 \pmod p \\
a_0 + a_1x_2 + a_2x_2^2 + \cdots + a_tx_2^t = y_2 \pmod p \\
\cdots \\
a_0 + a_1x_t + a_2x_t^2 + \cdots + a_tx_t^t = y_t \pmod p \\
\end{gather*}
$$


where $x_1, x_2, \cdots, x_t$ and $y_1, y_2, \cdots, y_t$ are known. $a_0, a_1, \cdots, a_t$ are unknown.

If the equations are not modular, i.e. without $\pmod p$, it is not solvable. However, modular gives us some opportunity that, there exists some $x$ satisfying $x^t = 1 \pmod p$.

If we can find such $x_i$, so that all $x_i^t = 1 \pmod p$, the equations become:

$$
\begin{gather*}
a_0 + a_1x_1 + a_2x_1^2 + \cdots + a_{t-1}x_1^{t-1} + a_t = y_1 \pmod p \\
a_0 + a_1x_2 + a_2x_2^2 + \cdots + a_{t-1}x_2^{t-1} + a_t = y_2 \pmod p \\
\cdots \\
a_0 + a_1x_t + a_2x_t^2 + \cdots + a_{t-1}x_t^{t-1} + a_t = y_t \pmod p \\
\end{gather*}
$$

$a_0 + a_t$ appears in all equations, and it becomes only one unknown coefficient as a whole. Then we have $t$ equations and $t$ unknown coefficients, and we can solve it using Lagrange Interpolation. After solving all coefficients, the secret is one of them. Do the same thing again, and find the intersection between two sets of coefficients, then solved.

So now the problem is, how to find the $x_1, x_2, \cdots, x_t$ that satisfy $x_i^t = 1 \pmod p$? Essentially, we are looking for a subgroup of order $t$. The order of the subgroup must be a factor of the order of the group $\mathbb{Z}_p$, which is $p-1$. After some attempts we can find that: $(p - 1) \bmod 29 = (2^{256} - 189 - 1) \bmod 29 = 0$. So $t = 29$ will work. Here is how the official writeup find such $x_i$:

```python
g = 2
while pow(g, (p-1)//t, p) == 1:
    g += 1

g = pow(g, (p-1)//t, p)
assert pow(g, t, p) == 1

shares = []
for i in range(t):
    x = pow(g, i, p)
    conn.sendline(str(x).encode())
    y = int(conn.recvline())
    shares.append((x, y))
```

Or we can use sage [Ring.zeta()](https://doc.sagemath.org/html/en/reference/rings/sage/rings/ring.html#sage.rings.ring.Ring.zeta) to find the roots:

```python
R = Integers(2**256-189)
root_list = R.zeta(29, all=True)
```
