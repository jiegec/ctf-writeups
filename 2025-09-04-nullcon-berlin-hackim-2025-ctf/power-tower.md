# Power tower

```
The code tells you how the key was computed, so all you have to do is execute this script.
```

The attachment contains the encryption code:

```python
from Crypto.Cipher import AES
from Crypto.Util import number

# n = number.getRandomNBitInteger(256)
n = 107502945843251244337535082460697583639357473016005252008262865481138355040617

primes = [p for p in range(100) if number.isPrime(p)]
int_key = 1
for p in primes: int_key = p**int_key

key = int.to_bytes(int_key % n,32, byteorder = 'big')

flag = open('flag.txt','r').read().strip()
flag += '_' * (-len(flag) % 16)
cipher = AES.new(key, AES.MODE_ECB).encrypt(flag.encode())
print(cipher.hex())
```

And the ciphertext:

```
b6c4d050dd08fd8471ef06e73d39b359e3fc370ca78a3426f01540985b88ba66ec9521e9b68821fed1fa625e11315bf9
```

However, computing the "power tower" is very slow:

```python
for p in primes: int_key = p**int_key
```

Since we only need `int_key % n`, we can simplify `a ** b % c` to `a ** (b % euler_phi(c)) % c` to make `b` smaller. The process can be done recursively to compute the power tower off `primes[-1] ** (primes[-2] ** (primes[-3] ** ...)) % n`:

```python
from Cryptodome.Cipher import AES
from Cryptodome.Util import number
from functools import reduce
from math import gcd
from sage.all import *

# n = number.getRandomNBitInteger(256)
n = 107502945843251244337535082460697583639357473016005252008262865481138355040617



def solve(primes, p):
    if len(primes) == 2:
        ret = pow(primes[0], primes[1], p)
    else:
        ret = pow(primes[-1], solve(primes[:-1], euler_phi(Integer(p))), p)
    return int(ret)


primes = [p for p in range(100) if number.isPrime(p)]
int_key = solve(primes, n)

key = int.to_bytes(int_key, 32, byteorder="big")

cipher = bytes.fromhex(open("cipher.txt", "r").read().strip())
flag = AES.new(key, AES.MODE_ECB).decrypt(cipher)
print(flag)
```

Get flag: `ENO{m4th_tr1ck5_c4n_br1ng_s0me_3ffic13ncy}`.
