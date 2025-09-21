# tricks

```
The only practical use case of cryptography.

Note: An old version of this challenge had the flag K17{90oOfy_LLL_P41Ll13R_PR08L3M}. This is no longer the flag.
nc challenge.secso.cc 7005 
```

Attachment:

```python
from Crypto.Util.number import getStrongPrime, long_to_bytes, bytes_to_long
from random import randint
from secrets import FLAG

assert len(FLAG) == 32

class Paillier:
    # en.wikipedia.org/wiki/Paillier_cryptosystem
    def __init__(self, p, q):
        self.n = p * q
        self.n2 = pow(self.n, 2)
        self.l = (p - 1) * (q - 1)
        self.mu = pow(self.l, -1, self.n)
        self.g = self.n + 1
        self.L = lambda x : (x - 1) // self.n
        
    def encrypt(self, m):
        return (pow(randint(1, self.n - 1), self.n, self.n2) * pow(self.g, m, self.n2)) % self.n2
        
    def decrypt(self, c):
        return (self.L(pow(c, self.l, self.n2)) * self.mu) % self.n


paillier = Paillier(getStrongPrime(1024), getStrongPrime(1024))
print(f"{paillier.n = }")

print(paillier.encrypt(bytes_to_long(FLAG)))
print("a key property of paillier encryption/decryption is that its homomorphic between the additive/multiplicative on the plaintext/ciphertext space")
print("the ability to anonymously add, or combine, encrypted streams is incredibly useful, one such application being")
print("TRICKS!!!")
print("YOU")
print("CAN")
print("DO")
print("TRICKS!!!!")
print("LET'S SEEE IF YOU CAN DO TRIIIIIICKS!!!!!!!!!!!!!!!!!!!!!!!!")
tricks = {
    "cha cha left": lambda x : x + b"\x00", # e.g. pow(x, 256, self.n2)
    "wave your hands": lambda x : b"\\_/-\\_/" + x + b"\\_/-\\_/",
    "SAY IT THREE TIMES": lambda x : x + x + x
}
print(f"you can {', '.join(tricks.keys())}... yeah that's pretty much it actually")
    
while True:
    trick = input("Which trick do you want to show me? ")
    if trick not in tricks:
        print("I've never heard of that trick before")
        continue

    
    x = int(input("What's the encrypted message you'd like to perform the trick on? "))
    y = int(input("What's the encrypted result of the trick? "))
    if bytes_to_long(tricks[trick](long_to_bytes(paillier.decrypt(x)))) == paillier.decrypt(y):
        print("HOLY SMOKES WHAT A TRICK!!!!!")
    else:
        print("nup.")
```

Initially, it seems unbreakable. However, the homomorphic proerty of Paillier crypto system holds under modulo n. The first trick, `cha cha left` multiplies 256 without modulo. So, if we enumerate i until `flag * (2**i) * 256 != flag * (2 ** i) * 256 mod n`, we know that `flag * (2 ** i) * 256 >= n`. It is somewhat similar to the parity oracle attack.

Next, we can subtract an `offset` from `flag` to make it smaller, and make a better estimate using the `(flag - offset) * (2 ** i) * 256 >= n` oracle by adding `n // 256 // (2 ** i)` to `offset`. Eventually `flag - offset` is small enough and `flag` is almost `offset`, except for the lowest byte, which is always `}`.

Attack script:

```python
from pwn import *
from Cryptodome.Util.number import getStrongPrime, long_to_bytes, bytes_to_long

# context(log_level="debug")
# p = process(["python3", "chall.py"])
p = remote("challenge.secso.cc", 7005)
n = int(p.recvline().decode().split()[2].strip())
flag_enc = int(p.recvline().decode().strip())

offset = 0
i = 2048 - 256 - 8
for round in range(32 * 8):
    while True:
        p.recvuntil(b"show me? ")
        p.sendline(b"cha cha left")
        p.recvuntil(b"trick on? ")
        # flag -= offset
        temp = flag_enc * pow(n + 1, n - offset, n**2)
        temp = pow(temp, 2**i, n**2)
        p.sendline(str(temp).encode())
        p.recvuntil(b"the trick? ")
        p.sendline(str(pow(temp, 256, n**2)).encode())
        result = p.recvline()
        print(i, result)
        if b"nup." in result:
            # (flag - offset) * (2**i) * 256 >= n
            bit = 2048 - i - 8
            offset += n // 256 // (2 ** i)
            print(long_to_bytes(offset))
            break
        i += 1
```

Flag: `K17{g0oofY_LLL_p@1ll1Er_pRo6l3m}`.
