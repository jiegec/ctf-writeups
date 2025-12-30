# bingo

Attachment:

```python
from Crypto.Util.number import getPrime, bytes_to_long, inverse, getRandomRange
import os

FLAG = os.getenv("FLAG", "TSGCTF{THIS_IS_FAKE}")

hash_p = getPrime(1024)
alpha = getRandomRange(2, hash_p - 1)
beta = getRandomRange(2, hash_p - 1)

def cvhp_hash(message_bytes):
    m = bytes_to_long(message_bytes)
    
    m_1 = m % (hash_p - 1)
    m_2 = m // (hash_p - 1)
    
    # ハッシュ計算
    # H = alpha^m_1 * beta^m_2 mod hash_p
    val1 = pow(alpha, m_1, hash_p)
    val2 = pow(beta, m_2, hash_p)
    h = (val1 * val2) % hash_p
    return h

# 検証ロジック
def verify(message_bytes, signature, N, e):
    h = cvhp_hash(message_bytes)
    
    if pow(signature, e, N) != h:
        return False
    
    return True

def check_message(message_bytes, signature, N, e):

    if not verify(message_bytes, signature, N, e):
        print("Signature verification failed.")

    if message_bytes.startswith(b"Get Flag."):
        print(FLAG)
    else:
        print("We have nothing to give you.")


p = getPrime(512)
q = getPrime(512)
N = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = inverse(e, phi)

print("N =", N)
print("e =", e)
print("hash_p =", hash_p)
print("alpha =", alpha)
print("beta =", beta)

massage_hex = input("input message (hex): ")
message_bytes = bytes.fromhex(massage_hex)

signature = int(input("input signature (int): "))

check_message(message_bytes, signature, N, e)
```

Even if the signature verfication failed, the flag can be printed. So simply:

```python
from pwn import *

#p = process(["python3", "server.py"])
p = remote("35.194.98.181", 10961)

p.sendline(b"Get Flag.".hex().encode())
p.sendline(b"0")
p.interactive()
```
