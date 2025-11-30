# Easy Random 3 WP

附件：

```python
import os
import random

flag = os.getenv("GZCTF_FLAG") or "flag{fake_flag_for_testing}"
rng = random.Random()

while True:
    print("Actions: (1) play a random guess game (2) guess the flag")
    action = int(input("Please input action:"))
    if action == 1:
        nbits = rng.randrange(1, 64)
        number = random.getrandbits(nbits)
        print("The random number is of", nbits, "bits")
        while True:
            guess = int(input("Enter your guess:"))
            if guess > number:
                print("Bigger")
            elif guess < number:
                print("Smaller")
            else:
                print("You win!")
                break
    elif action == 2:
        print("Guess the flag:")
        print(bytes([a ^ random.getrandbits(8) for a in flag.encode()]).hex())
        break
```

本题在 Easy Random 2 的基础上，修改了每次生成的随机数的位数，此时位数用的是一个单独的随机数生成器，和默认的随机数生成器分开。对于不再是 624 个 32 位随机数的情况，可以用 [gf2bv](https://github.com/maple3142/gf2bv) 等工具来建立针对 MT19937 内部状态的在 GF(2) 上的方程组，从而求解出随机数生成器的内部状态。使用的时候，只需要用它提供的接口，告诉它用什么参数生成的随机数的结果是多少。最后，就是和之前 Easy Random 2 一样的做法，推算出后续的随机数，求出 Flag。

```python
# pip3 install git+https://github.com/maple3142/gf2bv pwntools
from pwn import *
from gf2bv import LinearSystem
from gf2bv.crypto.mt import MT19937

p = process(["python3", "main.py"])

known = []
for i in range(1500):
    p.recvuntil(b"action:")
    p.sendline(b"1")
    nbits = int(p.recvline().decode().split()[5])
    left = 0
    right = 2**nbits - 1
    number = None
    while left < right:
        middle = (left + right) // 2
        p.recvuntil(b"guess:")
        p.sendline(str(middle).encode())
        resp = p.recvline().strip()
        if resp == b"Bigger":
            right = middle - 1
        elif resp == b"Smaller":
            left = middle + 1
        else:
            assert resp == b"You win!"
            number = middle
            break
    if number is None:
        p.recvuntil(b"guess:")
        p.sendline(str(left).encode())
        resp = p.recvline().strip()
        assert resp == b"You win!"
        number = left
    known.append((nbits, number))

# create equations
ls = LinearSystem([32] * 624)
gen = ls.gens()
rng = MT19937(gen)
zeros = [gen[0] ^ int(0x80000000)]
for nbits, value in known:
    zeros.append(rng.getrandbits(nbits) ^ value)

# found solutions
for sol in ls.solve_all(zeros):
    print("Solved")

    # recreate random number generator
    RNG = MT19937(sol).to_python_random()
    for nbits, value in known:
        assert RNG.getrandbits(nbits) == value

    p.recvuntil(b"action:")
    p.sendline(b"2")
    p.recvline()
    encoded = p.recvline().decode()
    flag = bytes([a ^ RNG.getrandbits(8) for a in bytes.fromhex(encoded)])
    print(flag)
    break
```
