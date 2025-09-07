# ECG

```
I heard that LCG can be cracked so I made my own PRNG - Exponential Congruence Generator. I used a large exponent so you can never predict it!
```

In attachment:

```python
from Crypto.Util.number import *
flag = "craccon{REDACTED}".encode()
message = flag[8:-1]
blocks = []

for i in range(len(message)//4):
  blocks.append(message[i*4:i*4+4])

n = bytes_to_long(blocks[0])
s0 =  bytes_to_long(blocks[1])
c = bytes_to_long(blocks[2])
m = bytes_to_long(blocks[3])

assert len(blocks)==4 

e = 2**65537
s=[]
s.append((s0*pow(m,e,n)+c)%n)
for i in range(10):
  s.append((s[-1]*pow(m,e,n)+c)%n)
print(s)
"[1471188920,8580498,528503476,577384753,534687615,631132756,1181691587,494356384,450508778,224733577,240456085]"
```

It is still a Linear Congruential Generator: $s_{n+1} = as_n + b \pmod n$, here $a = \mathrm{pow}(m, e, n), b = c$. So we need to recover $a, b, n$ first.

Following [Cracking a linear congruential generator](https://security.stackexchange.com/questions/4268/cracking-a-linear-congruential-generator), we can solve $n$ by:

1. compute differentials, $t_{n+1} = s_{n+1} - s_n = as_n + b - (as_{n-1} + b) = a(s_n - s_{n-1}) = at_n \pmod n$
2. so $t_{n+1}^2 - t_nt_{n+2} = 0 \pmod n$, we can solve $n$ by computing gcd of all $t_{n+1}^2 - t_nt_{n+2}$
3. now that `n` is known, we can find $a = t_{n+1}t_n^{-1} \pmod n$, and $b = s_{n+1} - as_n \pmod n$
4. the last thing is to solve $m^e = a \pmod n$, which is supported by sage `.nth_root()`

Code:

```python
from Cryptodome.Util.number import *
import math

# https://security.stackexchange.com/questions/4268/cracking-a-linear-congruential-generator
numbers = [
    1471188920,
    8580498,
    528503476,
    577384753,
    534687615,
    631132756,
    1181691587,
    494356384,
    450508778,
    224733577,
    240456085,
]
differential = []
for i in range(len(numbers) - 1):
    differential.append(numbers[i + 1] - numbers[i])

multiples = []
for i in range(len(differential) - 2):
    multiples.append(differential[i] * differential[i + 2] - differential[i + 1] ** 2)
n = math.gcd(*multiples)
print("n", long_to_bytes(int(n)))

# this is pow(m,e,n)
a = differential[2] * pow(differential[1], -1, n) % n
c = (numbers[1] - a * numbers[0]) % n
print("c", long_to_bytes(int(c)))

# solve pow(m,e,n)=a
e = 2**65537
K = GF(n)
ms = K(a).nth_root(e, all=True)
for m in ms:
    print("m", long_to_bytes(int(m)))

# solve (s0*a+c)%n=numbers[0]
s0 = (numbers[0] - c) * pow(a, -1, n) % n
print("s0", long_to_bytes(int(s0)))

print(
    long_to_bytes(int(n))
    + long_to_bytes(int(s0))
    + long_to_bytes(int(c))
    + long_to_bytes(int(m))
)
```

Output:

```
n b'Y0U_'
c b'K3D_'
m b'%\xed\x0e>'
m b'3CG!'
s0 b'CR4C'
b'Y0U_CR4CK3D_3CG!'
```

Note that there are more then one possible `m`, but only one of them corresponds to printable characters.

Flag: `CRACCON{Y0U_CR4CK3D_3CG!}`.
