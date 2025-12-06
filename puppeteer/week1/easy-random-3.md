# Easy Random 3 Writeup

## 题目描述

本题是 Easy Random 2 的进阶版本。程序使用两个独立的随机数生成器：

1. 一个用于生成随机数的位数（1-63 位）
2. 另一个用于生成实际的随机数

Flag 会与随机数进行异或加密后输出。

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

## 漏洞分析

Python 的 `random` 模块使用 Mersenne Twister (MT19937) 算法。虽然本题中随机数的位数是变化的，但 MT19937 的内部状态仍然是确定的。攻击的关键在于建立关于 MT19937 内部状态的方程组并求解。

## 攻击思路

1. **收集随机数样本**：通过二分法收集多个不同位数的随机数
2. **建立方程组**：使用 `gf2bv` 工具建立关于 MT19937 内部状态在 GF(2) 上的方程组
3. **求解方程组**：求解方程组得到 MT19937 的内部状态
4. **恢复 Flag**：使用恢复的状态预测后续随机数，解密加密的 Flag

## 解题步骤

### 1. 收集随机数样本

收集足够多的随机数样本（约 1500 个）：

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
```

### 2. 建立方程组

使用 `gf2bv` 建立关于 MT19937 内部状态的方程组：

```python
# create equations
ls = LinearSystem([32] * 624)
gen = ls.gens()
rng = MT19937(gen)
zeros = [gen[0] ^ int(0x80000000)]
for nbits, value in known:
    zeros.append(rng.getrandbits(nbits) ^ value)
```

### 3. 求解方程组

求解方程组得到 MT19937 的内部状态并恢复出 Flag：

```python
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

## 完整攻击脚本

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

## 局限性

`gf2bv` 工具的主要局限性在于：

1. **仅限于 GF(2) 运算**：只能处理在 GF(2) 上的线性运算
2. **特定算法**：主要针对 MT19937 算法，对于其他随机数生成器可能需要不同的方法

## 总结

本题展示了当随机数生成器的输出经过变换（如不同位数的截断）时，仍然可以通过建立方程组来恢复其内部状态。关键在于：

1. **理解随机数生成器的算法**：MT19937 的确定性使其容易受到此类攻击
2. **收集足够的样本**：需要足够多的观察结果来建立可解的方程组
3. **使用合适的工具**：`gf2bv` 等工具可以自动化方程组的建立和求解过程

对于涉及更复杂运算的随机数生成器，可能需要使用其他方法，如符号执行或约束求解。
