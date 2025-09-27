# Gotam

```
Calling Gotam a "challenge" is like calling a nap "extreme sports" :D

nc 65.109.194.34 13131
```

Attachment:

```python
#!/usr/bin/env python3

import sys
from Crypto.Util.number import *
from flag import flag

def die(*args):
    pr(*args)
    quit()

def pr(*args):
    s = " ".join(map(str, args))
    sys.stdout.write(s + "\n")
    sys.stdout.flush()

def sc():
    return sys.stdin.buffer.readline()

def check_nr(a, p, q):
    return pow(a, (p - 1) // 2, p) == p - 1 and pow(a, (q - 1) // 2, q) == q - 1

def gotam(nbit):
    p, q = [getPrime(nbit) for _ in ':)']
    n = p * q
    while True:
        t = getRandomRange(1, n - 1)
        if check_nr(t, p, q):
            break
    return (n, t), (p, q)

def encrypt(msg, pubkey):
    n, t = pubkey
    M = bin(bytes_to_long(msg))[2:].zfill(1 << 10)
    l = len(M)
    E = [
        t ** int(M[_]) * getRandomNBitInteger(n.bit_length() - 1) ** 2 % n
        for _ in range(l)
    ]
    return E

def main():
    border = "┃"
    pr(
        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
    )
    pr(
        border,
        "Unlock Gotam's tailored encryption—can you outsmart this custom asymmetric enigma?",
        border,
    )
    pr(
        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"
    )
    pubkey, privkey = gotam(128)
    del privkey
    while True:
        pr(
            f"{border} Options: \n{border}\t[E]ncrypt flag \n{border}\t[P]ublic data \n{border}\t[Q]uit"
        )
        ans = sc().decode().strip().lower()
        if ans == "e":
            enc = encrypt(flag, pubkey)
            for e in enc:
                pr(border, f"{hex(e) = }")
        elif ans == "p":
            pr(border, "n, t = ", ", ".join(map(hex, pubkey)))
        elif ans == "q":
            die(border, "Quitting...")
        else:
            die(border, "Bye...")

if __name__ == "__main__":
    main()
```

It is an implementation of [Goldwasser-Micali cryptosystem](https://en.wikipedia.org/wiki/Goldwasser%E2%80%93Micali_cryptosystem), which is safe except for the small primes. So we can directly factor 256-bit `n` into `p` and `q`, and recover the flag.

Attack script in sage:

```python
from Crypto.Util.number import *
from pwn import *

context(log_level = "debug")

#p = process(["python3", "gotam.py"])
p = remote("65.109.194.34", 13131)

p.recvuntil(b"[Q]uit")
p.sendline(b"p")
p.recvline()
res = p.recvline().decode()
n = int(res.split()[4][:-1], 16)
t = int(res.split()[5], 16)
print(n, t)

p.recvuntil(b"[Q]uit")
p.sendline(b"e")
p.recvline()
e = []
while True:
    line = p.recvline().decode()
    if "hex(e)" in line:
        e.append(int(line.split()[3][1:-1], 16))
    else:
        break

print(len(e))

factors = Integer(n).factor()
print(factors)
p = factors[0][0]
q = factors[1][0]
print(p, q)

M = ""
for i in e:
    # check if quadratic residue
    if pow(i, (p - 1) // 2, p) == 1 and pow(i, (q - 1) // 2, q) == 1:
        M += "0"
    else:
        M += "1"
msg = long_to_bytes(int(M, 2))
print(msg)
```

Flag: `ASIS{Priv4te_c0mpari5oN_iZ_fundAm3ntaL_7O_s3cuRe_mult1pArtY_cOmpuTatIons!}`.
