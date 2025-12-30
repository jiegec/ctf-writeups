# layers

```
Bro's larping again
nc challenge.secso.cc 7004 
```

Attachment:

```python
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime
from Crypto.Cipher import AES
from random import randint, randbytes
from secrets import FLAG

class LayeredEncryption:
    def __init__(self, p, q, aes_key):
        assert len(aes_key) == 16
        self.n = p * q
        self.aes_key = aes_key
        self.e = 65537
        self.d = pow(self.e, -1, (p - 1) * (q - 1))

    def encrypt(self, m):
        iv = randbytes(16)
        aes_c = bytes_to_long(iv + AES.new(self.aes_key, AES.MODE_CBC, iv).encrypt(pad(m, 16)))

        print(aes_c)

        r = randint(1, 2**512 - 1)
        ri = pow(r, -1, self.n)
        return (r, pow(ri * aes_c, self.e, self.n), pow(ri * aes_c, self.d, self.n)) # salt, encrypted ciphertext, signature of ciphertext
        

    def decrypt(self, r, c, s):
        if r < 1 or r >= 2**512:
            print("Salt must a positive integer less than 2^512")
        elif c != pow(s, self.e * self.e, self.n):
            print("Signature is invalid!")
        else:
            aes_c_bytes = long_to_bytes((pow(c, self.d, self.n) * r) % self.n)
            iv, ciphertext = aes_c_bytes[:16], aes_c_bytes[16:]
            return unpad(AES.new(self.aes_key, AES.MODE_CBC, iv).decrypt(ciphertext), 16)


e = LayeredEncryption(getPrime(1024), getPrime(1024), randbytes(16))
r, c, s = e.encrypt(FLAG)
print(f"{e.n = }")
print(f"{e.e = }")
print("Welcome to my lair of layers!")
print(f"Foolish traveller! You think you can best all of my schemes!??! Here, a challenge: {(r, c, s)}")


while True:
    guess = input("Prithee, tell in a comma-separated triplet, what secret do i hold? ")
    try:
        if e.decrypt(*map(int, guess.split(","))) == FLAG:
            print("yes, AND IT SHALL NEVER SEE THE LIGHT OF DAY!")
        else:
            print("NAY!")
    except:
        print(f"what is bro doing 💀")
```

There are two parts:

1. Bypass the signature validation by setting `c == s == 1`
2. Padding oracle attack

The signature validation bypass is suggested by DeepSeek:

```
To solve this CTF challenge, we need to provide a triplet \((r', c', s')\) that decrypts to the FLAG using the `LayeredEncryption` class's `decrypt` method. The key insight is that we can compute the value \(A\) (the `aes_c` value) from the given triplet \((r, c, s)\) using the formula \(A = r \times s^e \mod n\). Once we have \(A\), we can form a new triplet \((A, 1, 1)\) that bypasses the signature check and decrypts to the FLAG.

### Step-by-Step Solution:
1. **Obtain the values \(n\), \(e\), \(r\), \(c\), and \(s\) from the challenge output.**
   - The challenge outputs `e.n`, `e.e`, and the triplet \((r, c, s)\).

2. **Compute \(A = r \times s^e \mod n\).**
   - This \(A\) is the `aes_c` value, which is the long integer representing the IV and AES-encrypted FLAG.

3. **Form the new triplet \((A, 1, 1)\).**
   - This triplet satisfies the decrypt method's check because \(c' = 1\) and \(s' = 1\), so \(s'^{e^2} \mod n = 1\), which equals \(c'\).
   - During decryption, computing \(c'^d \times r' \mod n\) gives \(1^d \times A = A\), which is the required `aes_c` value.

4. **Provide the triplet \((A, 1, 1)\) as input when prompted.**
   - The decrypt method will successfully decrypt this to the FLAG.

### Python Implementation:
Here is a Python script that computes \(A\) and outputs the triplet for input:

from Crypto.Util.number import long_to_bytes, bytes_to_long

# Given values from the challenge output
n = ...  # from e.n
e = ...  # from e.e
r = ...  # from the triplet
c = ...  # from the triplet
s = ...  # from the triplet

# Compute A = r * s^e mod n
A = (r * pow(s, e, n)) % n

# Form the triplet (A, 1, 1)
triplet = f"{A},1,1"

print(triplet)

When the challenge prompts for input, provide the output of this script. The decrypt method will then return the FLAG.

### Explanation:
- The original triplet \((r, c, s)\) is encrypted such that \(A\) can be derived from \(r\) and \(s\) using public exponent \(e\) and modulus \(n\).
- The new triplet \((A, 1, 1)\) exploits the decrypt method's check by using \(c' = 1\) and \(s' = 1\), which always satisfies \(c' = s'^{e^2} \mod n\).
- The decryption computation \(c'^d \times r' \mod n\) becomes \(1 \times A = A\), which is then decrypted with the AES key (known to the object) to obtain the FLAG.

This approach efficiently bypasses the need for the private key or AES key by leveraging the public values and the properties of modular arithmetic.
```

The padding oracle attack part:

```python
from pwn import *
from Cryptodome.Util.number import long_to_bytes, bytes_to_long, getPrime

context(log_level="debug")

# p = process(["python3", "layer.py"])
p = remote("challenge.secso.cc", 7004)
aes_c = int(p.recvline().decode().strip())
n = int(p.recvline().decode().strip().split()[-1])
e = int(p.recvline().decode().strip().split()[-1])
p.recvuntil(b"challenge: (")
r = int(p.recvuntil(b", ").decode().split(",")[0])
c = int(p.recvuntil(b", ").decode().split(",")[0])
s = int(p.recvuntil(b")").decode().split(")")[0])


def find(msg):
    iv = [0] * 16
    iv[0] = 0xFF  # to avoid long_to_bytes dropping prefix
    known = [0] * 16
    # padding oracle attack
    for i in range(1, 17):
        good = []
        for j in range(1, i):
            iv[16 - j] = known[16 - j] ^ i
        for ch in range(256):
            iv[16 - i] = ch

            new_aes_c = bytes_to_long(bytes(iv) + msg)
            print(bytes(iv) + msg)
            p.recvuntil(b"i hold? ")
            # c = s = 1
            p.sendline(f"{new_aes_c},1,1".encode())
            res = p.recvline()
            if b"what is bro doing" not in res:
                good.append(ch)
        if len(good) == 1:
            known[16 - i] = i ^ good[0]
        else:
            print(good)
            assert False
    return known


data = long_to_bytes(aes_c)

res = find(data[16:32])
plain1 = bytes([x ^ y for x, y in zip(data[0:16], res)])
print(plain1)

res = find(data[32:48])
plain2 = bytes([x ^ y for x, y in zip(data[16:32], res)])
print(plain1 + plain2)

res = find(data[48:64])
plain3 = bytes([x ^ y for x, y in zip(data[32:48], res)])
print(plain1 + plain2 + plain3)

p.interactive()
```

Flag: `K17{WH47_4_kwIRKy_P4DDin9_0r4CL3}`.
