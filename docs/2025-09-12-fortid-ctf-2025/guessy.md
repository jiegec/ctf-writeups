# Guessy

```
Don't you love guessy challenges?

nc 0.cloud.chals.io 32957 
```

```python
#!/usr/bin/python3

import math
import signal
import sys

from Crypto.Util.number import getPrime, inverse, getRandomRange

N_BITS = 512

class A:
    def __init__(self, bits = N_BITS):
        self.p = getPrime(bits // 2)
        self.q = getPrime(bits // 2)
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.e = 0x10001
        self.d = pow(self.e, -1, self.phi)


    def encrypt(self, m):
        return pow(m, self.e, self.n)


    def decrypt(self, c):
        return pow(c, self.d, self.n)


class B:
    def __init__(self, bits = N_BITS):
        self.p = getPrime(bits // 2)
        self.q = getPrime(bits // 2)
        self.n = self.p * self.q
        self.n_sq = self.n * self.n
        self.g = self.n + 1
        self.lam = (self.p - 1) * (self.q - 1) // math.gcd(self.p - 1, self.q - 1)
        x = pow(self.g, self.lam, self.n_sq)
        L = (x - 1) // self.n
        self.mu = inverse(L, self.n)


    def encrypt(self, m):
        r = getRandomRange(1, self.n)
        while math.gcd(r, self.n) != 1:
            r = getRandomRange(1, self.n)
        c1 = pow(self.g, m, self.n_sq)
        c2 = pow(r, self.n, self.n_sq)
        return (c1 * c2) % self.n_sq


    def decrypt(self, c):
        x = pow(c, self.lam, self.n_sq)
        L = (x - 1) // self.n
        return (L * self.mu) % self.n


def err(msg):
    print(msg)
    exit(1)


def compute(e_secret, xs, a, b):
    ret = 1
    for x in xs:
        ret *= a.encrypt(b.decrypt(e_secret * x))
        ret %= a.n
    return ret


def ans(secret, qs, a, b):
    e_secret = b.encrypt(secret + 0xD3ADC0DE)
    for i in range(7):
        li = qs[i][:len(qs[i]) // 2]
        ri = qs[i][len(qs[i]) // 2:]

        print(f"{compute(e_secret, li, a, b)} {compute(e_secret, ri, a, b)}")


def test(t):
    print(f"--- Test #{t} ---")
    a = A()
    b = B()
    print(f"n = {b.n}")
    print("You can ask 7 questions:")

    qs = []
    for _ in range(7):
        l = list(map(int, input().strip().split()))
        if len(l) % 2 != 0:
            err("You must give me an even number of numbers!")
        if len(l) != len(set(l)):
            err("All numbers must be distinct!")
        qs.append(l)

    secret = getRandomRange(16, 2048)
    ans(secret, qs, a, b)

    print("Can you guess my secret?")
    user = int(input())

    if user != secret:
        err("Seems like you can't")
    else:
        print("Correct!")


def timeout_handler(signum, frame):
    print("Timeout!")
    sys.exit(1)

def main():
    signal.signal(signal.SIGALRM, timeout_handler)

    for i in range(10):
        test(i)

    flag = open('flag.txt', "r").read()
    print(f"Here you go: {flag}")

if __name__ == '__main__':
    main()
```

The core logic:

```python
def compute(e_secret, xs, a, b):
    ret = 1
    for x in xs:
        ret *= a.encrypt(b.decrypt(e_secret * x))
        ret %= a.n
    return ret


def ans(secret, qs, a, b):
    e_secret = b.encrypt(secret + 0xD3ADC0DE)
    for i in range(7):
        li = qs[i][:len(qs[i]) // 2]
        ri = qs[i][len(qs[i]) // 2:]

        print(f"{compute(e_secret, li, a, b)} {compute(e_secret, ri, a, b)}")
```

`A` is a typical RSA encryption, `B` is Paillier cryptosystem. Utilizing the properties of Paillier, `b.decrypt(e_secret * pow(b.g, x, b.n_sq)) == b.decrypt(b.encrypt(secret + 0xD3ADC0DE) * pow(b.g, x, b.n_sq)) == secret + 0xD3ADC0DE`. So we can send `pow(b.g, b.n - 0xD3ADC0DE, b.n_sq)` to recover the RSA encrypted secret: `pow(secret, a.e, a.n)`.

Since `secret = getRandomRange(0, 2048)`, we can bruteforce the secret from `[0, 2048]`, and find n by computing gcd of `pow(secret, a.e) - pow(secret, a.e, n)`. To accelerate attack, parallel computation is implemented. Attack script:

```python
import tqdm
from pwn import *
import multiprocessing
import time
from multiprocessing import Process, Queue


def worker_function(secrets, q):
    res = None
    for secret in secrets:
        # we known pow(secret - i, 65537, n), solve n
        nums0 = pow(secret - 0, 65537) - int(recv[0])
        nums1 = pow(secret - 1, 65537) - int(recv[1])
        n = math.gcd(nums0, nums1)
        if n < 2**510:
            continue

        for j in range(2, 14):
            numsj = pow(secret - j, 65537) - int(recv[j])
            n = math.gcd(n, numsj)
            if n < 2**510:
                break

        if n >= 2**510:
            res = secret
            break

    q.put(res)


if __name__ == "__main__":
    context(log_level="debug")

    p = process(["python3", "server.py"])
    # p = remote("0.cloud.chals.io", 32957)
    for i in range(10):
        p.recvuntil(b"n = ")
        n = int(p.recvline().decode())
        print(n)
        g = n + 1
        n_sq = n * n

        values = []
        for i in range(14):
            values.append(pow(g, n - 0xD3ADC0DE - i, n_sq))

        p.recvuntil(b"questions:")
        res = None
        for i in range(7):
            p.sendline(f"{values[2*i]} {values[2*i+1]}".encode())
        p.recvline()

        recv = []
        for i in range(7):
            parts = p.recvline().decode().strip().split()
            recv += parts

        # enumerate secret
        # find n
        parallel = 64
        secrets = list(range(0, 2048))
        share = len(secrets) // parallel

        procs = []
        q = Queue()
        for i in range(parallel):
            proc = multiprocessing.Process(
                target=worker_function, args=(secrets[i * share : (i + 1) * share], q)
            )
            proc.start()
            procs.append(proc)

        for i in range(parallel):
            temp = q.get()
            if temp is not None:
                res = temp

        for i in range(parallel):
            procs[i].join()

        if res is not None:
            p.recvuntil(b"secret?")
            p.sendline(str(res).encode())
        print(res)

    p.interactive()
```

Flag: `FortID{Y0u_R_4_Phr3ak1n6_M1nd_R3ad3r!_orz_orz}`.
