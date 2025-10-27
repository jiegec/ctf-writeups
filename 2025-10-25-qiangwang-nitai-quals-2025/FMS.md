# FMS

附件：

```python
import os
import pty
from Crypto.Util.number import *
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from hashlib import sha256
from random import randrange
from string import ascii_letters, digits

flag = os.getenv('FLAG')

class PRNG:
    def __init__(self, a=None, b=None, p=None, seed=None):
        self.p = p if p else getPrime(128)
        self.a = a if a else randrange(1, self.p)
        self.b = b if b else randrange(0, self.p)
        self.state = seed if seed else randrange(0, self.p)

    def next(self):
        self.state = (self.a * self.state + self.b) % self.p
        return self.state

    def randbytes(self, n):
        out = b''
        for _ in range(n):
            out += bytes([self.next() % 256])
        return out

    def choices(self, seq, k):
        return [seq[self.next() % len(seq)] for _ in range(k)]

    def getPrime(self, n):
        while True:
            num = self.randbytes(n // 8)
            p = bytes_to_long(num) | (1 << (n - 1)) | 1
            if isPrime(p):
                return p

    def getrandbits(self, n):
        num = self.randbytes((n + 7) // 8)
        return bytes_to_long(num) & ((1 << n) - 1)

    def __repr__(self):
        return f'a = {self.a}\nb = {self.b}\np = {self.p}'

prng = PRNG()

Account = {"admin": sha256(("".join(prng.choices(ascii_letters + digits, 32))).encode()).hexdigest(),
           "guest": "84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"}

user = None

menu = """Flag Management System
[L]ogin
[G]et Public Key
[R]ead Flag
[E]xit"""

if __name__ == "__main__":
    while True:
        print(menu)
        op = input(">>> ").strip().upper()

        if op == "L" or op == "LOGIN":
            vcode = prng.randbytes(4).hex().rjust(8, '0')
            print(f"Verification code: {vcode}")
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            verify = input("Verification code: ").strip()

            if verify != vcode:
                print("Verification code error!")
                continue

            if username in Account and Account[username] == sha256(password.encode()).hexdigest():
                print(f"Welcome, {username}!")
                user = username

            else:
                print("Login failed!")

        elif op == "G" or op == "GET PUBLIC KEY":
            print(prng)

        elif op == "R" or op == "READ FLAG":
            if user == "admin":
                key = prng.randbytes(16)
                iv = prng.randbytes(16)
                aes = AES.new(key, AES.MODE_CBC, iv)
                print(aes.encrypt(pad(flag.encode(), 16)).hex())
            else:
                print("Permission denied!")

        elif op == "E" or op == "EXIT":
            print("Goodbye!")
            exit(0)
            
        else:
            print("Invalid option!")
```

本题需要通过多轮 Verification code，恢复出一个 Truncated LCG Generator 的 Seed，然后得到 admin 密码，登录成功后，再计算出 key 和 iv，对 flag 进行解密。Truncated LCG Generator 的求解见 [之前的总结](../misc/lcg.md)。

攻击代码：

```python
from pwn import *
from fpylll import *
from Crypto.Util.number import *
from Crypto.Cipher import AES


# https://github.com/ajuelosemmanuel/Truncated_LCG_Seed_Recovery/blob/main/attack_exemple_lsb.py
def attack(a: int, b: int, p: int, lsb: bool, shift: int, Ys: list):
    # the problem is:
    # x_{i+1} = (ax_i + b) \bmod p
    # recover x_0

    # compute the value before division for approximation
    if lsb:
        I = pow(2**shift, -1, p)
    else:
        I = 2**shift
    y = [(el * I) % p for el in Ys]

    # cancel b by adding b(a-1)^{-1}
    # x_{i+1} = (ax_i + b) \bmod p
    # z_i = x_i + b(a-1)^{-1}
    # z_{i+1} = (x_{i+1} + b(a-1)^{-1}) \bmod p
    #         = (ax_i + b + b(a-1)^{-1}) \bmod p
    #         = (ax_i + ab(a-1)^{-1}) \bmod p
    #         = (az_i) \bmod p
    if lsb:
        z = [
            (y[i] + b * pow(a - 1, -1, p) * pow(2**shift, -1, p)) % p
            for i in range(len(y))
        ]
    else:
        z = [(y[i] + b * pow(a - 1, -1, p)) % p for i in range(len(y))]

    # construct row vectors as a matrix
    size = len(z)
    matrix = [[0] * size for _ in range(size)]
    for i in range(size):
        matrix[0][i] = pow(a, i, p)
    for i, j in zip(range(1, size), range(1, size)):
        if i == j:
            matrix[i][j] = p

    # find closest vector to y
    L = IntegerMatrix.from_matrix(matrix)
    reduced = LLL.reduction(L)
    Xi_I = CVP.closest_vector(reduced, z, method="fast")

    # seed is the first element, drop the extra coefficient
    probable_seed = Xi_I[0] % p
    if lsb:
        probable_seed = (probable_seed * (2**shift)) % p
    probable_seed = (probable_seed - b * pow(a - 1, -1, p)) % p

    # recover the generated values
    probable_ys = []
    x = probable_seed
    for i in range(len(Ys)):
        if lsb:
            probable_ys.append(x % (2**shift))
        else:
            probable_ys.append(x // (2**shift))
        x = (a * x + b) % p

    print("Seed recovery success:", probable_ys == Ys)
    return probable_seed


context(log_level="DEBUG")
p = process(["python3", "main.py"])

# get parameters
p.recvuntil(b">>> ")
p.sendline(b"G")
p.recvuntil(b"a = ")
a = int(p.recvline().decode())
p.recvuntil(b"b = ")
b = int(p.recvline().decode())
p.recvuntil(b"p = ")
modulus = int(p.recvline().decode())

# get some random bytes
nums = []
for i in range(5):
    p.recvuntil(b">>> ")
    p.sendline(b"LOGIN")
    p.recvuntil(b"Verification code: ")
    vcode = bytes.fromhex(p.recvline().decode())
    p.sendline()
    p.sendline()
    p.sendline()
    nums += [int(b) for b in vcode]

print(f"{a = }")
print(f"{b = }")
print(f"{modulus = }")
seed = attack(a, b, modulus, True, 8, nums)
print(f"{seed = }")

# verify
state = seed
for i in range(len(nums)):
    assert nums[i] == state % 256
    state = (a * state + b) % modulus

# find password of admin, reverse 32 steps
state = seed
for i in range(32):
    state = (state - b) * pow(a, -1, modulus) % modulus

# generate admin password
seq = string.ascii_letters + string.digits
password = ""
for i in range(32):
    password += seq[state % len(seq)]
    state = (a * state + b) % modulus

assert state == seed

# login as admin
p.recvuntil(b">>> ")
p.sendline(b"LOGIN")
p.recvuntil(b"Verification code: ")
vcode = p.recvline()
p.recvuntil(b"Username: ")
p.sendline(b"admin")
p.recvuntil(b"Password: ")
p.sendline(password.encode())
p.recvuntil(b"Verification code: ")
p.send(vcode)
print(password)

# now logged in
p.recvuntil(b">>> ")
p.sendline(b"READ FLAG")

enc = bytes.fromhex(p.recvline().decode().strip())

# generate key
# compute state before generation key and iv
state = seed
for i in range(len(nums) + 4):
    state = (a * state + b) % modulus

key = []
for i in range(16):
    key.append(state % 256)
    state = (a * state + b) % modulus

iv = []
for i in range(16):
    iv.append(state % 256)
    state = (a * state + b) % modulus

aes = AES.new(bytes(key), AES.MODE_CBC, bytes(iv))

print(aes.decrypt(enc))
```

