# flag lottery

```
i love gambling, don't you?

nc challs3.pyjail.club 24908
```

Attachment:

```python
#!/usr/local/bin/python3
import secrets
import random
from lottery_machine import flag

x = [*"%&()*,./:;>[]^{|}~"] # i deleted a bunch of characters because i just dislike them for being too cool.
random.shuffle(x)
charset = x[:4]
print(f'your lucky numbers are: {", ".join([str(ord(i)) for i in charset])}')
charset += ["_"]
count = 0

try:
    while count < 100:
        _ = secrets.token_bytes(128)
        secret = _
        for z in range(1025):
            code = input("cmd: ")
            if code == "submit":
                if input("lottery numbers? ") == secret.hex():
                    count += 1
                else:
                    raise ValueError("the winning ticket was " + secret.hex())
            elif any(i not in charset for i in code):
                raise ValueError("invalid cmd")
            else:
                try:
                    eval(code)
                except:
                    print("answering machine broke.")
except Exception as err:
    print(err)
if count == 100:
    print(f"you won! here is {flag:}")
else:
    print("better luck next time!")
```

Not solved in competition. It requires us to reveal the 128 random bytes under 1024 attempts. So each byte corresponds to `1024/128=8` attempts, which is suited for binary search because `log2(256)=8`. Therefore, my approach is to check if `_[index] > number`, then do a binary search on each `_[index]`. To convert the check to the exception side channel, we use `arr[_[index]]` where arr is an array of length `number`. However, I can only think of a way to use 5 extra characters:

1. To constrct array, `[[], [], []]` to construct an array of element 3
2. To compute `_[index]`, use `_[1:][1:][0]` for `_[2]`, where `1` can be computed from `[[]]>[]`, `0` can be computed from `[]>[]`

However, it requires `[]>:,`, five characters. We can only use four. The attack script for the relaxed constraints:

```python
# TODO: reduce to 4 chars
# charset = [*"[]>,:"]
from pwn import *

# context(log_level="debug")

p = process(["python3", "flag_lottery.py"])
count = 0
while count < 100:
    print(count)
    p.recvuntil(b"cmd: ")
    data = bytearray()
    z = 0
    for i in range(128):
        lo = 0
        hi = 256
        while lo + 1 < hi:
            # print(i, lo, hi)
            mi = (lo + hi) // 2
            # ch = _[i]
            # arr[ch] without exception: ch < len(arr)
            arr = "[" + ",".join(["[]"] * mi) + "]"
            if i > 0:
                # arr[1:][1:][0]
                index = "_" + "".join(["[[[]]>[]:]"] * i) + "[[]>[]]"
            else:
                # arr[0]
                index = "_[[]>[]]"
            p.sendline(f"{arr}[{index}]".encode())
            z += 1
            resp = p.recvuntil(b"cmd:")
            if b"broke" in resp:
                # out of bounds, ch >= mi
                lo = mi
            else:
                # ch < mi
                hi = mi
        data.append(lo)
    while z < 1025:
        p.sendline(b"submit")
        p.recvuntil(b"numbers?")
        p.sendline(data.hex().encode())
        z += 1
        count += 1
p.interactive()
```

A possibility is to use `_` for the array of length 128, and use `_[1:][1:]` to construct an array of length 125. However, we cannot represent array of length 129 or greater.

Another primitive is `[[]][condition]`, so that if the `condition` evaluates to True, an exception is raised.

After the competition ends, solutions are posted on Discord:

```
@minaminao

I used >[]^
just curious, are there any other solutions? https://gist.github.com/minaminao/a4ef6c022bf9b129e52145500476cd21
```

So the idea is:

1. find the first byte of the secret, by shifting `_[0]` by some bits, e.g. `_[0]>>1>>1`, then toggling one bit from it: `[_[0]>>1>>1][0]^1` and comparing it with itself: `[_[0]>>1>>1][0]^1>[_[0]>>1>>1][0]`, finally converting the condition to exception side channel: `[[]][[_[0]>>1>>1][0]^1>[_[0]>>1>>1][0]]`; if it raises exception, we know that the bit was 0, so that toggling the bit makes it larger
2. the second byte can be found in the same way, since we can do the same thing to `_[1]`
3. now that we know `_[0]` and `_[1]`, we can use them to deduce other bytes, for example, `_[_[0]]`, `_[_[1]]`, `_[_[0]^_[1]]` etc; the process is the same as in previous steps

Eventually we will be able to recover the whole secret.
