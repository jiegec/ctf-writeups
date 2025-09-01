# ssss

```
https://www.zkdocs.com/docs/zkdocs/protocol-primitives/alt-shamir/#moving-away-from-the-constant-term

nc ctfi.ng 31555
```

Attachment:

```python
#!/usr/local/bin/python3
import random

p = 2**255 - 19
k = 15
SECRET = random.randrange(0, p)

print("welcome to ssss")
# Step 1: Generate a random, degree-(k−3) polynomial g(x)
g = [random.randrange(p) for _ in range(k - 2)]
# Step 2: Select a random c in Fp
c = random.randrange(0, p)
# Step 3: Set f(x)=g(x)x^2+Sx+c
f = [c] + [SECRET] + g

def evaluate_poly(f, x):
    return sum(c * pow(x, i, p) for i, c in enumerate(f)) % p

for _ in range(k - 1):
    x = int(input())
    assert 0 < x < p, "no cheating!"
    print(evaluate_poly(f, x))

if int(input("secret? ")) == SECRET:
    FLAG = open("flag.txt").read()
    print(FLAG)
```

We are given a polynomial of 14 degree with 15 random coefficients. We can query 14 points on the polynomial, and need to extract the coefficient before $x$: $S$ in  $f(x)=g(x)x^2+Sx+c$.

Initially, I though it can be solved in a similar way to [ssss in SekaiCTF 2025](../2025-08-16-sekaictf2025/ssss.md), by using a primitive root. However, the field here, does not have a 14-order root anymore:

```python
sage: (2**255-19).factor()
2^2 * 3 * 65147 * 74058212732561358302231226437062788676166966415465897661863160754340907
```

We can have 12-order root, but we cannot compute `S`: If we use the same algorithm from [ssss in SekaiCTF 2025](../2025-08-16-sekaictf2025/ssss.md), we can use 12 points to make $x^{12}$ equals to $1$, but at the same time, $x^{13}$ equals to $x$ and $x^{14}$ equals to $x^2$. We cannot distinguish the coefficient before $x^{13}$ and $x$. Maybe there is some way to solve this, I did not figure it out in the competition.

After the competition ends, I found a solution at [c240030/corCTF-2025](https://github.com/c240030/corCTF-2025/blob/main/ssss/solve.py), which uses a novel way to solve the problem:

Since we want to compute the coefficient before $x$, we can eliminate the coefficients for the even-ordered coefficients by using a pair of $x_1$ and $-x_1$:

$$
\begin{gather*}
a_0 + a_1x_1 + a_2x_1^2 + a_3x_1^3 + \cdots + a_{14}x_1^{14} = y_1 \pmod p \\
a_0 + a_1(-x_1) + a_2(-x_1)^2 - a_3(-x_1)^3 +\cdots + a_{14}(-x_1)^{14} = y_1' \pmod p \\
2(a_1x_1 + a_3x_1^3 + \cdots + a_{13}x_1^{13}) = y_1 - y_1' \pmod p \\
a_1 + a_3x_1^2 + \cdots + a_{13}x_1^{12} = (y_1 - y_1')/2/x_1 \pmod p \\
\end{gather*}
$$

This way, we only have 7 unknown coefficients: $a_0, a_3, \cdots, a_{13}$. We can get 7 equations by asking $7*2$ points on the polynomial, which exactly matches the requirement. The solution:

```python
from pwn import *
from sage.all import *

context(log_level="debug")
# p = process(["python3", "./ssss.py"])
p = remote(host="ctfi.ng", port="31555")

prime = 2**255 - 19
R = Integers(prime)


def mod_inverse(a, m):
    """Calculates the modular multiplicative inverse of a modulo m."""
    return pow(a, m - 2, m)


p.recvuntil("ssss")
p.recvline()
shares = []
for i in range(1, 8):
    # evaluate at i
    x = i
    p.sendline(str(x).encode())
    y1 = int(p.recvline().strip())

    # evaluate at -i
    x = prime - i
    p.sendline(str(x).encode())
    y2 = int(p.recvline().strip())

    real_x = pow(i, 2, prime)
    numerator = (y1 - y2 + prime) % prime
    denominator_inv = mod_inverse(2 * i, prime)
    real_y = (numerator * denominator_inv) % prime
    shares.append((real_x, real_y))
print(shares)
R = GF(2**255 - 19)["x0"]
res = list(R.lagrange_polynomial(shares))
p.recvuntil("secret?")
p.sendline(str(res[0]).encode())
p.interactive()
```

Get flag: `corctf{ill_come_up_with_a_good_flag_later_maybe}`.
