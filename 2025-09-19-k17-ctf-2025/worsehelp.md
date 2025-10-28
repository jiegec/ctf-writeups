# worsehelp

```
my betterhelp therapist turned out to be a sham

:(. my new one told me to use rsa. huh?
nc challenge.secso.cc 7008 
```

Attachment:

```python
from Crypto.Util.number import isPrime, getStrongPrime
from os import urandom
from math import gcd
from secrets import FLAG

a, b = map(int, input("Enter your secure parameters a, b (as comma-separated values) to seed the RNG: ").split(","))

if a.bit_length() < 1024 or b.bit_length() < 1024 or not isPrime(a) or isPrime(b):
    print("Your parameters are not secure")
    quit()

p, q = getStrongPrime(1024), getStrongPrime(1024)

n = p * q
phi = (p - 1) * (q - 1)


# to harden d
r = ((a**2 + b**2 + 3*a + 3*b + a*b) * pow(2 * a * b + 7, -1, phi)) % phi

while gcd(k := int.from_bytes(urandom(32), "big"), phi) != 1:
    continue

d = pow(k, r, phi)
d |= 1

e = pow(d, -1, phi)

m = int.from_bytes(FLAG, "big")
c = pow(m, e, n)

print(f"{c = }")
print(f"{e = }")
print(f"{n = }")
```

If we can make `r` small, then `d` will be small too. To make `r` small, try different possibilities of the equations below:

```
a**2+b**2+3*a+3*b+a*b == 1*(2*a*b + 7)
a**2+b**2+3*a+3*b+a*b == 2*(2*a*b + 7)
a**2+b**2+3*a+3*b+a*b == -1*(2*a*b + 7)
a**2+b**2+3*a+3*b+a*b == -2*(2*a*b + 7)
a**2+b**2+3*a+3*b+a*b == 0
```

Through <www.alpertron.com.ar/QUAD.HTM>, we find infinite solutions for the following equation:

```
 x² - 3 ⁢x⁢y + y² + 3 ⁢x + 3 ⁢y - 14 ⁢ = 0

x = 2
y = 4
and also:

x = 4
y = 2
xn+1 = 3 ⁢xn - yn - 3 ⁢
yn+1 =  xn

and also:
xn+1 =  yn
yn+1 = - xn + 3 ⁢yn - 3 ⁢ 
```

We just following the iteration until we found a valid pair of `a, b`. Then, `r = 2` and we can use Wiener's attack:

```python
from pwn import *
from Cryptodome.Util.number import isPrime, getStrongPrime, getPrime
import os

context(log_level="debug")


# make a**2+b**2+3*a+3*b+a*b == 2*(2*a*b + 7)
# b**2 + (3-3*a)*b + a**2+3*a-14 == 0

# solve using https://www.alpertron.com.ar/QUAD.HTM

a = 2
b = 4
for i in range(1000):
    assert b**2 + (3 - 3 * a) * b + a**2 + 3 * a - 14 == 0
    a, b = b, -a + 3 * b - 3
    if (
        a.bit_length() >= 1024
        and b.bit_length() >= 1024
        and isPrime(a)
        and not isPrime(b)
    ):
        print(a, b)
        break

#p = process(["python3", "worsehelp.py"])
p = remote("challenge.secso.cc", 7008)
p.recvuntil(b"RNG: ")
p.sendline(f"{a},{b}".encode())
# now r == 2
c = int(p.recvline().decode().strip().split()[2])
e = int(p.recvline().decode().strip().split()[2])
n = int(p.recvline().decode().strip().split()[2])
print(n, e, c, file=open("worsehelp.txt", "w"))
os.system("sage worsehelp-attack.sage")
```

The sage part is learn from <https://cryptohack.gitbook.io/cryptobook/untitled/low-private-component-attacks/wieners-attack>:

```python
# worsehelp-attack.sage
from Crypto.Util.number import long_to_bytes

def wiener(e, n):
    # Convert e/n into a continued fraction
    cf = continued_fraction(e/n)
    convergents = cf.convergents()
    for kd in convergents:
        k = kd.numerator()
        d = kd.denominator()
        # Check if k and d meet the requirements
        if k == 0 or d%2 == 0 or e*d % k != 1:
            continue
        phi = (e*d - 1)/k
        # Create the polynomial
        x = PolynomialRing(RationalField(), 'x').gen()
        f = x^2 - (n-phi+1)*x + n
        roots = f.roots()
        # Check if polynomial as two roots
        if len(roots) != 2:
            continue
        # Check if roots of the polynomial are p and q
        p,q = int(roots[0][0]), int(roots[1][0])
        if p*q == n:
            return d
    return None

if __name__ == '__main__':
    n, e, c = [Integer(int(x)) for x in open("worsehelp.txt", "r").read().split()]
    print(n, e, c)
    d = wiener(e,n)
    assert not d is None, "Wiener's attack failed :("
    print(long_to_bytes(int(pow(c,d,n))).decode())
```

Flag: `K17{v137a_83A75_5MAlL_ds_aNy_daY}`.
