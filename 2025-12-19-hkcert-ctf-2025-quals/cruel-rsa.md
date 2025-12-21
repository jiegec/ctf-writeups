# cruel_rsa

Attachment:

```python
from sage.all import *  
from sage.crypto.util import random_blum_prime
from Crypto.Util.number import *
from secret import flag

nbit = 512
gamma = 0.44
delta = 0.51
dm,dl = 0.103, 0.145
cpbit = ceil(nbit * gamma) 
kbit  = int(nbit * delta)
msbit = int(nbit * dm)
lsbit = int(nbit * dl)
g = random_blum_prime(2**(cpbit - 1), 2**cpbit-1)  
while 1:
    p = q = 0
    while is_prime(p) or len(bin(p)) - 2 != nbit // 2:
        a = randint(int(2 ** (nbit // 2 - 2) // g * gamma), 2 ** (nbit // 2 - 1) // g)
        p = 2 * g * a + 1 
    while is_prime(q) or len(bin(q)) - 2 != nbit // 2:
        b = randint(int(2 ** (nbit // 2 - 2) // g * gamma), 2 ** (nbit // 2 - 1) // g)
        q = 2 * g * b + 1
    L = 2 * g * a * b   
    if is_prime(L + a + b):
        n = p * q
        break

d = random_prime(2**kbit-1, lbound=2**(kbit - 1)) 
e = inverse_mod(d, L)
k = (e * d - 1) // L
dm = d // (2 ** (kbit - msbit))
dl = d % (2 ** lsbit)
m = bytes_to_long(flag)
print(dm, dl, e, n)
print(pow(m, e, n))
"""
3203202584971257 7274383203268085152331 36346110007425305872660997908648011390452485009167380402907988449045651435844811625907 8073736467273664280056643912209398524942152147328656910931152412352288220476046078152045937002526657533942284160476452038914249779936821603053211888330755
8042279705649954745962644909235780183674555369775538455015331686608683922326562829164835918982642084136603628007677118144681339970688028985720674063973679
"""
```

The `n` is composite and factorable:

```
n = 3^2 * 5 * 11 * 13 * 241 * 19913 * 27479 * 8817293 * 1609668743 * 21744410757863 * 1791152102074579 * 2640729780285917881567 * 561544524741926577700278571 * 11606767999414698455890262045272382868998286949
```

So we can compute euler phi and recover `m`. However, the result is wrong, because `n` and `m` are not coprime.

Instead, we recover `m` modulo each prime factor of `n`, and use Chinese Remainder Theorm to recover `m`.

Attack script:

```python
from Crypto.Util.number import *
from sage.all import *

n = 8073736467273664280056643912209398524942152147328656910931152412352288220476046078152045937002526657533942284160476452038914249779936821603053211888330755
c = 8042279705649954745962644909235780183674555369775538455015331686608683922326562829164835918982642084136603628007677118144681339970688028985720674063973679
e = 36346110007425305872660997908648011390452485009167380402907988449045651435844811625907
# factor 3^2 * 5 * 11 * 13 * 241 * 19913 * 27479 * 8817293 * 1609668743 * 21744410757863 * 1791152102074579 * 2640729780285917881567 * 561544524741926577700278571 * 11606767999414698455890262045272382868998286949
factors = [
    3,
    5,
    11,
    13,
    241,
    19913,
    27479,
    8817293,
    1609668743,
    21744410757863,
    1791152102074579,
    2640729780285917881567,
    561544524741926577700278571,
    11606767999414698455890262045272382868998286949,
]
assert n // product(factors) == 3
phi = n
for factor in factors:
    phi = phi * (factor - 1) // factor
d = pow(e, -1, phi)
print("phi", phi)

m = pow(c, d, n)
print(long_to_bytes(m))

ms = []
for factor in factors:
    ms.append(pow(c, d, factor))

print(long_to_bytes(crt(ms, factors)))
```