# Easy Random 2 Writeup

## 题目描述

本题是 Easy Random 1 的 Python 版本。程序使用 Python 的 `random` 模块生成随机数，允许用户进行两种操作：

1. 玩一个猜数字游戏（数字范围 $[0, 2^{32}-1]$）
2. 猜测 Flag（Flag 会与随机数进行异或加密后输出）

附件：

```python
import os
import random

flag = os.getenv("GZCTF_FLAG") or "flag{fake_flag_for_testing}"

while True:
    print("Actions: (1) play a random guess game (2) guess the flag")
    action = int(input("Please input action:"))
    if action == 1:
        number = random.getrandbits(32)
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

Python 的 `random` 模块使用 Mersenne Twister 算法作为伪随机数生成器。该算法在已知 624 个连续的 32 位随机数后，可以完全预测后续的所有随机数输出。

## 攻击思路

1. **收集随机数样本**：通过二分法玩猜数字游戏，收集 624 个 `random.getrandbits(32)` 的结果
2. **恢复随机数状态**：使用 `randcrack` 库将收集到的随机数提交，恢复 Mersenne Twister 的内部状态
3. **恢复 Flag**：使用恢复的状态预测后续随机数，解密加密的 Flag

## 解题步骤

### 1. 收集随机数样本

使用二分法收集 624 个 32 位随机数：

```python
# pip3 install randcrack pwntools
from pwn import *

p = process(["python3", "main.py"])

for i in range(624):
    p.recvuntil(b"action:")
    p.sendline(b"1")
    left = 0
    right = 2**32 - 1
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
```

### 2. 恢复随机数状态

使用 `randcrack` 库恢复 Mersenne Twister 的内部状态：

```python
from randcrack import RandCrack
rc = RandCrack()
for i in range(624):
    # we got number from remote
    rc.submit(number)
```

### 3. 恢复 Flag

使用恢复的状态预测后续随机数，解密加密的 Flag：

```python
p.recvuntil(b"action:")
p.sendline(b"2")
p.recvline()
encoded = p.recvline().decode()
flag = bytes([a ^ rc.predict_getrandbits(8) for a in bytes.fromhex(encoded)])
print(flag)
```

## 完整攻击脚本

```python
# pip3 install randcrack pwntools
from pwn import *
from randcrack import RandCrack

p = process(["python3", "main.py"])

rc = RandCrack()

for i in range(624):
    p.recvuntil(b"action:")
    p.sendline(b"1")
    left = 0
    right = 2**32 - 1
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
    rc.submit(number)

p.recvuntil(b"action:")
p.sendline(b"2")
p.recvline()
encoded = p.recvline().decode()
flag = bytes([a ^ rc.predict_getrandbits(8) for a in bytes.fromhex(encoded)])
print(flag)
```

## 总结

本题展示了 Python `random` 模块的 Mersenne Twister 算法的弱点。虽然该算法在统计上具有良好的随机性，但在密码学上并不安全。一旦攻击者获得了足够多的连续随机数输出（624 个 32 位整数），就可以完全预测后续的所有随机数。

对于更复杂的随机数恢复场景（如非连续的随机数输出或经过变换的随机数），可以使用更强大的工具如 [gf2bv](https://github.com/maple3142/gf2bv)。
