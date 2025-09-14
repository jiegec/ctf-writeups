# Crypto

```
These keys look completely different, yet they have something in common...
```

Attachment contains two public keys:

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm1PtORdHA6pyJn9fU2Gh
grU4v+tPnCX1ji+Dih/qn0ze/NrX3ci21JjCOGp4TW2z24gaCI5MwWWvof89iYQ3
9ZXyw5c5AR1cG7y+HSwC8HASBwlp3zZ62hJmafZd684dWEyUfqUvlggStvWr2BLy
Pr3udlrPvEFoX0t5Ooy/4xAiYM/X9iv9Y8DVvEyOnctWocrVJuFLXHcogINUGgIT
jJ7ol84OXZrG18P1Dqq+KO8qNzrvVb1NNTVjFbC6Jh8d9Zm5onu1jxWQ1pZWz3AB
7aFA+Yl90kEhksECLgXXVJiTm3EFpRHO0nP2VgGHu6ZHZ3D6ay2CXIduO+yqlPK0
oQIDAQAB
-----END PUBLIC KEY-----
```

and

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAubHpZY/hQ0+PIp7UoM1P
npvLsaxxWi3rrZX3lTKbHtTBeN6r84/ahgWuLeS6KOV1P1tGTP5H0GIdWDLqfFa3
ua6s6ZZLghliWF5okQay7WVf/Et84sMyR3wj/rCq7ttu26U72DTeSKlL/hiUqYuj
mHUM1zhRMfgL4iNWQhK3Viv6Cfru+PF9U0awDI8rv2AVkorHe6bIDfkcpKPSjhSB
H409hU8TRVCUNjs7BUMWE1EgdLy/NEChGG+rHUTIptioIYSkUVuGR4PuojEzDtZ2
cOb8Aza3orkMFC4Xt8gRyZJad0/WyJruj9sgURJv6r110qrrCos3F86RsYtl9Uz3
6QIDAQAB
-----END PUBLIC KEY-----
```

Through the hints in the problem description, the two public keys may share a common prime factor:

```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import *
from Crypto.Cipher import PKCS1_OAEP
import Crypto
import math

key1 = RSA.import_key(open("key1.pub", "rb").read())

key2 = RSA.import_key(open("key2.pub", "rb").read())

p = math.gcd(key1.n, key2.n)
q1 = key1.n // p
q2 = key2.n // p

# decrypt
d1 = pow(key1.e, -1, (p - 1) * (q1 - 1))
k1 = RSA.construct((key1.n, key1.e, d1, p, q1))
print(k1)

d2 = pow(key2.e, -1, (p - 1) * (q2 - 1))
k2 = RSA.construct((key2.n, key2.e, d2, p, q2))
print(k2)

open("key1.pem", "wb").write(k1.export_key())
open("key2.pem", "wb").write(k2.export_key())
```

However, directly decrypting the `flag{1,2}.enc` files does not work. After some attempts, the hash function must be sha256 for it to work:

```python
flag1 = bytes.fromhex(open("flag1.enc", "r").read())
open("flag1", "wb").write(flag1)
cipher = PKCS1_OAEP.new(k1, Crypto.Hash.SHA256)
print(cipher.decrypt(flag1))

flag2 = bytes.fromhex(open("flag2.enc", "r").read())
open("flag2", "wb").write(flag2)
cipher = PKCS1_OAEP.new(k2, Crypto.Hash.SHA256)
print(cipher.decrypt(flag2))
```

Flag: `FortID{4nd_1_Sa1d_Wh47_Ab07_4_C0mm0n_Pr1m3_F4ct0r?}`.
