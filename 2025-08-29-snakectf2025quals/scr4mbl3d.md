# Scr4mbl3d

```
I like to confuse people. (Or I'm the one confused?)
```

Attachment provided a python script:

```python
#!/usr/bin/env python3

import sys
from os import path
from random import randint
from hashlib import sha256

P = 112100829556962061444927618073086278041158621998950683631735636667566868795947
ROUNDS = randint(26, 53)
CONSTANT = [(44 * i ^ 3 + 98 * i ^ 2 + 172 * i + 491) % P for i in range(ROUNDS)]
EXPONENT = 3


def split(x):
    chunk1 = x // P
    chunk2 = x % P
    return chunk1, chunk2


def merge(chunk1, chunk2):
    return chunk1 * P + chunk2


def ff(x):
    return ((x * EXPONENT) * 0x5DEECE66D) % P


def gg(x):
    digest = sha256(int(x).to_bytes(256)).digest()
    return int.from_bytes(digest) % P


def transform(x, y, i):
    u = x
    if i % 11 == 0:
        v = (y + ff(u)) % P
    else:
        v = (y + gg(u)) % P
    v = (v + CONSTANT[i]) % P
    return v, u


def encrypt(input):
    chunk1, chunk2 = split(input)
    for i in range(ROUNDS):
        if i % 5 == 0:
            chunk1, chunk2 = transform(chunk1, chunk2, i)
        else:
            chunk2, chunk1 = transform(chunk2, chunk1, i)
    output = merge(chunk1, chunk2)
    return output


if __name__ == "__main__":
    out_dir = sys.argv[1]
    flag = sys.argv[2].encode()

    input = int.from_bytes(flag)
    ciphertext = encrypt(input)

    with open(path.join(out_dir, "out.txt"), "w") as f:
        f.write(hex(ciphertext))
```

And the `out.txt`:

```
0x8c864ced6d0a2461cfd9f0ae986d9c5d077b66179bcff166ea2754445683ac4e727bf27d58da1ad196064f6170f6b7e1c7754432400ef80ce27bcb44c29336d7
```

So we need to reverse the encryption process to decrypt. However, there are some unknown parameters:

1. little or big endian in `int.to_bytes()`
2. `ROUNDS = randint(26, 53)`

We just enumerate them to find the flag:

```python
#!/usr/bin/env python3

import sys
from os import path
from random import randint
from hashlib import sha256

P = 112100829556962061444927618073086278041158621998950683631735636667566868795947
EXPONENT = 3


def split(x):
    chunk1 = x // P
    chunk2 = x % P
    return chunk1, chunk2


def merge(chunk1, chunk2):
    return chunk1 * P + chunk2


def ff(x):
    return ((x * EXPONENT) * 0x5DEECE66D) % P


def gg(x):
    digest = sha256(int(x).to_bytes(256, "big")).digest()
    return int.from_bytes(digest, "big") % P


def transform(x, y, i, rounds):
    CONSTANT = [(44 * i ^ 3 + 98 * i ^ 2 + 172 * i + 491) % P for i in range(rounds)]
    v, u = x, y
    v = (v - CONSTANT[i]) % P
    if i % 11 == 0:
        y = (v - ff(u) + P) % P
    else:
        y = (v - gg(u) + P) % P
    x = u
    return x, y


def decrypt(input, rounds):
    chunk1, chunk2 = split(input)
    for i in range(rounds - 1, -1, -1):
        if i % 5 == 0:
            chunk1, chunk2 = transform(chunk1, chunk2, i, rounds)
        else:
            chunk2, chunk1 = transform(chunk2, chunk1, i, rounds)
    output = merge(chunk1, chunk2)
    return output


if __name__ == "__main__":
    with open("out.txt", "r") as f:
        ciphertext = int(f.read().strip(), 16)
        for rounds in range(26, 54):
            flag = decrypt(ciphertext, rounds)
            data = flag.to_bytes(100, "big")
            if b"CTF" in data:
                print(data)
```

Get flag: `snakeCTF{Ev3ry7hing_1s_34s13r_w1th_F3is7el_8dd17148a55cf01e}`
