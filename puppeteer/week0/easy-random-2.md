# Easy Random 2 WP

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

本题在 Easy Random 1 的基础上，把随机数生成器换成了 Python，其余的逻辑一样。攻击的思路是，首先通过二分通关前面的猜随机数环节，然后把随机数传给 [randcrack](https://github.com/tna0y/Python-random-module-cracker)，它可以逆向出 Python 随机数生成器的内部状态，进而推算后续生成的随机数，求出 Flag。

首先是通过二分进行猜随机数，只需要猜 624 次即可：

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

接下来，就可以用 randcrack 进行攻击：

```python
from randcrack import RandCrack
rc = RandCrack()
for i in range(624):
    # we got number from remote
    rc.submit(number)
```

最终，根据恢复出来的随机数得到 Flag，完整的攻击脚本如下：

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

但是，randcrack 只能支持比较简单的随机数恢复场景，对于更复杂的情况，会用到 [gf2bv](https://github.com/maple3142/gf2bv)。
