# stream-cipher-fans-when

```
Written by virchau13

They don't call it a CHF for nothing
```

Attachment:

```python
import numpy as np, itertools, random

CHUNK_SIZE = 256
shared_key = np.random.permutation(np.arange(CHUNK_SIZE))

def apply_perm(chunk):
    global shared_key
    assert len(chunk) == CHUNK_SIZE
    return np.array(list(chunk), dtype=np.uint8)[shared_key]

def chf(data):
    state = np.zeros(CHUNK_SIZE, dtype=np.uint8)
    for i in range(0, len(data), CHUNK_SIZE):
        chunk = data[i:i+CHUNK_SIZE]
        chunk += b'\0'*(CHUNK_SIZE-len(chunk))
        state ^= apply_perm(chunk)
    return bytes(state.tolist())

def csprng():
    counter = 0
    while True:
        block = chf((1337*str(counter)).encode())
        yield block
        counter += 1

def encrypt(data):
    for enc_block in csprng():
        plain_block = data[:CHUNK_SIZE]
        if len(plain_block) == 0:
            break
        plain_block += b'\0'*(CHUNK_SIZE - len(plain_block))
        cipher_block = bytes([x^y for x,y in zip(plain_block, enc_block)])
        yield cipher_block
        data = data[CHUNK_SIZE:]

with open('AIW.txt', 'rb') as f:
    aiw = f.read()[random.randint(0, 1000):]

with open('encrypted.bin', 'wb') as f:
    for block in encrypt(aiw):
        f.write(block)
```

The program generates key using `chf` and xors with data in `AIW.txt`, starting from random offset. Since the first key `chf(0)` is constant regardless of the private key, we can find the correct offset:

```python
CHUNK_SIZE = 256
f = open("encrypted.bin", "rb")
data = f.read()
aiw = open("AIW-truncated.txt", "rb").read()
for offset in range(0, 1000):
    plain_block = aiw[offset : offset + CHUNK_SIZE]
    cipher_block = data[0:CHUNK_SIZE]
    enc_block = bytes([x ^ y for x, y in zip(plain_block, cipher_block)])
    if b"00000000" in enc_block:
        # found correct offset
        print(enc_block, offset)
        break
```

Then for `chf(1)` to `chf(9)`, we know that the bytes of the keys can only have two possibilities and their location is the same. Since we know the plaintext, we can deduce `chf(1)` is:

```
b'1111111111111\x001111\x001111\x001111\x0011\x001\x001111\x0011\x00\x00\x00\x0011111111\x00111111\x00111111111\x001\x00\x0011111111111111\x00\x00\x
001\x0011111\x00\x0011111\x0011\x001\x00\x001111111111\x00\x00111\x001\x001\x00\x00\x00111111\x00111111111111111111\x001111111\x001\x00\x00\x0011\x0
0111111111\x0011\x00\x00111111\x001111\x00111\x001\x00\x00\x001111111111111\x0011111111\x001111111111\x00111\x0011\x0011\x00\x00\x001'
```

For `chf(10)`, the key may contain `\x00`, `"1"` or `"0"`. So we use known plaintext to recover the key:

```python
j = CHUNK_SIZE * 10
cipher_block = data[j : j + CHUNK_SIZE]
plain_block = b"his time?\xe2\x80\x9d she said aloud. \xe2\x80\x9cI must be\r\ngetting somewhere near the centre of the earth. Let me see: that would\r\nbe four thousand miles down, I think\xe2\x80\x94\xe2\x80\x95 (for, you see, Alice had learnt\r\nseveral things of this sort in her lessons in the schoolroom, and though this"
print(len(plain_block))
recons.write(plain_block)
temp_enc_block = bytes([x ^ y for x, y in zip(plain_block, cipher_block)])
for i in range(len(temp_enc_block)):
    if (
        temp_enc_block[i] != 0
        and temp_enc_block[i] != ord("0")
        and temp_enc_block[i] != ord("1")
    ):
        print(
            i,
            temp_enc_block[i],
            chr(cipher_block[i]),
            chr(cipher_block[i] ^ ord("1")),
            chr(cipher_block[i] ^ ord("0")),
        )
        print(plain_block[i:])
        break
print(temp_enc_block)
```

By replacing `1` and `0` to other digits, we can find all keys of `chf(11)` to `chf(99)`:

```python
for i in range(11, 100):
    # 10 -> xy
    last_enc_block = (
        temp_enc_block.replace(b"0", b"x")
        .replace(b"1", b"y")
        .replace(b"x", str(i % 10).encode())
        .replace(b"y", str(i // 10).encode())
    )
    j = CHUNK_SIZE * i
    cipher_block = data[j : j + CHUNK_SIZE]
    plain_block = bytes([x ^ y for x, y in zip(last_enc_block, cipher_block)])
    print(plain_block)
    recons.write(plain_block)
```

Then, we manually recover `chf(100)`, `chf(101)` and `chf(102)` using known plaintext:

```python
j = CHUNK_SIZE * 100
cipher_block = data[j : j + CHUNK_SIZE]
plain_block = b" advisable to go with Edgar Atheling to meet William and offer him\r\nthe crown. William\xe2\x80\x99s conduct at first was moderate. But the insolence\r\nof his Normans\xe2\x80\x94\xe2\x80\x99 How are you getting on now, my dear?\xe2\x80\x9d it continued,\r\nturning to Alice as it spoke.\r\n\r\n\xe2\x80\x9cAs "
print(len(plain_block))
recons.write(plain_block)
temp_enc_block = bytes([x ^ y for x, y in zip(plain_block, cipher_block)])
for i in range(len(temp_enc_block)):
    if (
        temp_enc_block[i] != 0
        and temp_enc_block[i] != 1
        and temp_enc_block[i] != ord("0")
        and temp_enc_block[i] != ord("1")
    ):
        print(
            i,
            temp_enc_block[i],
            repr(chr(cipher_block[i])),
            repr(chr(cipher_block[i] ^ 1)),
            repr(chr(cipher_block[i] ^ ord("1"))),
            repr(chr(cipher_block[i] ^ ord("0"))),
        )
        print(plain_block[i:])
        break
print(temp_enc_block)
enc_block_100 = temp_enc_block

j = CHUNK_SIZE * 101
cipher_block = data[j : j + CHUNK_SIZE]
plain_block = b"wet as ever,\xe2\x80\x9d said Alice in a melancholy tone: \xe2\x80\x9cit doesn\xe2\x80\x99t seem to\r\ndry me at all.\xe2\x80\x9d\r\n\r\n\xe2\x80\x9cIn that case,\xe2\x80\x9d said the Dodo solemnly, rising to its feet, \xe2\x80\x9cI move\r\nthat the meeting adjourn, for the immediate adoption of more energetic\r\nremedies\xe2\x80\x94\xe2\x80\x9d"
print(len(plain_block))
recons.write(plain_block)
temp_enc_block = bytes([x ^ y for x, y in zip(plain_block, cipher_block)])
for i in range(len(temp_enc_block)):
    if (
        temp_enc_block[i] != 0
        and temp_enc_block[i] != 1
        and temp_enc_block[i] != ord("0")
        and temp_enc_block[i] != ord("1")
    ):
        print(
            i,
            cipher_block[i],
            repr(chr(cipher_block[i])),
            repr(chr(cipher_block[i] ^ 1)),
            repr(chr(cipher_block[i] ^ ord("1"))),
            repr(chr(cipher_block[i] ^ ord("0"))),
        )
        print(plain_block[i:])
        break
print(temp_enc_block)
enc_block_101 = temp_enc_block

j = CHUNK_SIZE * 102
cipher_block = data[j : j + CHUNK_SIZE]
plain_block = b"\r\n\r\n\xe2\x80\x9cSpeak English!\xe2\x80\x9d said the Eaglet. \xe2\x80\x9cI don\xe2\x80\x99t know the meaning of half\r\nthose long words, and, what\xe2\x80\x99s more, I don\xe2\x80\x99t believe you do either!\xe2\x80\x9d And\r\nthe Eaglet bent down its head to hide a smile: some of the other birds\r\ntittered audibly.\r\n\r\n\xe2\x80\x9c"
print(len(plain_block))
recons.write(plain_block)
temp_enc_block = bytes([x ^ y for x, y in zip(plain_block, cipher_block)])
for i in range(len(temp_enc_block)):
    if (
        temp_enc_block[i] != 0
        and temp_enc_block[i] != 1
        and temp_enc_block[i] != 2
        and temp_enc_block[i] != 3
        and temp_enc_block[i] != ord("0")
        and temp_enc_block[i] != ord("1")
        and temp_enc_block[i] != ord("2")
        and temp_enc_block[i] != ord("3")
    ):
        print(
            i,
            cipher_block[i],
            repr(chr(cipher_block[i])),
            repr(chr(cipher_block[i] ^ 1)),
            repr(chr(cipher_block[i] ^ 2)),
            repr(chr(cipher_block[i] ^ 3)),
            repr(chr(cipher_block[i] ^ ord("1"))),
            repr(chr(cipher_block[i] ^ ord("0"))),
            repr(chr(cipher_block[i] ^ ord("2"))),
            repr(chr(cipher_block[i] ^ ord("3"))),
        )
        print(plain_block[i:])
        break
print(temp_enc_block)
enc_block_102 = temp_enc_block
```

The key is a xor-combination of three bytes of `str(counter)`, so we classify each byte of key using `chf(100)`, `chf(101)` and `chf(102)`:

```python
# classify each byte, 100/101/102 -> xyz, xor between xyz and \x00
res = []
for a, b, c, index in zip(enc_block_100, enc_block_101, enc_block_102, range(256)):
    if a == 0 and b == 1 and c == 2:
        res.append("y xor z")
    elif a == 1 and b == 1 and c == 1:
        res.append("x xor y")
    elif a == 1 and b == 0 and c == 3:
        res.append("x xor z")
    elif a == 49 and b == 48 and c == 51: # 103
        res.append("x xor y xor z")
    else:
        res.append("unknown")
        print(index, ":", a, b, c)
```

At last, we can recover all `chf(103)` to `chf(999)` keys using the information:

```python
for i in range(103, 1000):
    x = str(i // 100).encode()
    y = str((i / 10) % 10).encode()
    z = str(i % 10).encode()
    # 100/101 -> xyz
    last_enc_block = bytearray()
    for type in res:
        if type == "y xor z":
            last_enc_block.append(y[0] ^ z[0])
        elif type == "x xor y":
            last_enc_block.append(x[0] ^ y[0])
        elif type == "x xor z":
            last_enc_block.append(x[0] ^ z[0])
        elif type == "x xor y xor z":
            last_enc_block.append(x[0] ^ y[0] ^ z[0])
        else:
            last_enc_block.append(0)
    j = CHUNK_SIZE * i
    cipher_block = data[j : j + CHUNK_SIZE]
    if len(cipher_block) == 0:
        break
    plain_block = bytes([x ^ y for x, y in zip(last_enc_block, cipher_block)])
    # print(plain_block)
    recons.write(plain_block)
```

In the reconstructed file, at 2249th row:

```
“Of course it is,” said the Duchess, who seemed ready to agree to
everything that Alice said; “there’s a large mustard-mine near here.
And the moral of that is—‘The more there is of mine, the less there is
of yours.’”

watctf{https://graydon2.dreamwidth.org/319755.html}

“Oh, I know!” exclaimed Alice, who had not attended to this last
remark, “it’s a vegetable. It doesn’t look like one, but it is.”
```

The flag is `watctf{https://graydon2.dreamwidth.org/319755.html}`.

Full code:

```python
CHUNK_SIZE = 256
f = open("encrypted.bin", "rb")
data = f.read()
aiw = open("AIW-truncated.txt", "rb").read()
for offset in range(0, 1000):
    plain_block = aiw[offset : offset + CHUNK_SIZE]
    cipher_block = data[0:CHUNK_SIZE]
    enc_block = bytes([x ^ y for x, y in zip(plain_block, cipher_block)])
    if b"00000000" in enc_block:
        # found correct offset
        print(enc_block, offset)
        break

recons = open("AIW-reconstructed.txt", "wb")
for j in range(0, CHUNK_SIZE * 9, CHUNK_SIZE):
    plain_block = aiw[offset + j : offset + j + CHUNK_SIZE]
    cipher_block = data[j : j + CHUNK_SIZE]
    enc_block = bytes([x ^ y for x, y in zip(plain_block, cipher_block)])
    print(enc_block, plain_block.decode())
    recons.write(plain_block)

j = CHUNK_SIZE * 7
plain_block = aiw[offset + j : offset + j + CHUNK_SIZE]
cipher_block = data[j : j + CHUNK_SIZE]
enc_block = bytes([x ^ y for x, y in zip(plain_block, cipher_block)])
print(enc_block)

last_enc_block = enc_block.replace(b"7", b"8")
j = CHUNK_SIZE * 8
cipher_block = data[j : j + CHUNK_SIZE]
plain_block = bytes([x ^ y for x, y in zip(last_enc_block, cipher_block)])
print(plain_block)

last_enc_block = enc_block.replace(b"7", b"9")
j = CHUNK_SIZE * 9
cipher_block = data[j : j + CHUNK_SIZE]
plain_block = bytes([x ^ y for x, y in zip(last_enc_block, cipher_block)])
print(plain_block)
recons.write(plain_block)

j = CHUNK_SIZE * 10
cipher_block = data[j : j + CHUNK_SIZE]
plain_block = b"his time?\xe2\x80\x9d she said aloud. \xe2\x80\x9cI must be\r\ngetting somewhere near the centre of the earth. Let me see: that would\r\nbe four thousand miles down, I think\xe2\x80\x94\xe2\x80\x95 (for, you see, Alice had learnt\r\nseveral things of this sort in her lessons in the schoolroom, and though this"
print(len(plain_block))
recons.write(plain_block)
temp_enc_block = bytes([x ^ y for x, y in zip(plain_block, cipher_block)])
for i in range(len(temp_enc_block)):
    if (
        temp_enc_block[i] != 0
        and temp_enc_block[i] != ord("0")
        and temp_enc_block[i] != ord("1")
    ):
        print(
            i,
            temp_enc_block[i],
            chr(cipher_block[i]),
            chr(cipher_block[i] ^ ord("1")),
            chr(cipher_block[i] ^ ord("0")),
        )
        print(plain_block[i:])
        break
print(temp_enc_block)

for i in range(11, 100):
    # 10 -> xy
    last_enc_block = (
        temp_enc_block.replace(b"0", b"x")
        .replace(b"1", b"y")
        .replace(b"x", str(i % 10).encode())
        .replace(b"y", str(i // 10).encode())
    )
    j = CHUNK_SIZE * i
    cipher_block = data[j : j + CHUNK_SIZE]
    plain_block = bytes([x ^ y for x, y in zip(last_enc_block, cipher_block)])
    print(plain_block)
    recons.write(plain_block)

j = CHUNK_SIZE * 100
cipher_block = data[j : j + CHUNK_SIZE]
plain_block = b" advisable to go with Edgar Atheling to meet William and offer him\r\nthe crown. William\xe2\x80\x99s conduct at first was moderate. But the insolence\r\nof his Normans\xe2\x80\x94\xe2\x80\x99 How are you getting on now, my dear?\xe2\x80\x9d it continued,\r\nturning to Alice as it spoke.\r\n\r\n\xe2\x80\x9cAs "
print(len(plain_block))
recons.write(plain_block)
temp_enc_block = bytes([x ^ y for x, y in zip(plain_block, cipher_block)])
for i in range(len(temp_enc_block)):
    if (
        temp_enc_block[i] != 0
        and temp_enc_block[i] != 1
        and temp_enc_block[i] != ord("0")
        and temp_enc_block[i] != ord("1")
    ):
        print(
            i,
            temp_enc_block[i],
            repr(chr(cipher_block[i])),
            repr(chr(cipher_block[i] ^ 1)),
            repr(chr(cipher_block[i] ^ ord("1"))),
            repr(chr(cipher_block[i] ^ ord("0"))),
        )
        print(plain_block[i:])
        break
print(temp_enc_block)
enc_block_100 = temp_enc_block

j = CHUNK_SIZE * 101
cipher_block = data[j : j + CHUNK_SIZE]
plain_block = b"wet as ever,\xe2\x80\x9d said Alice in a melancholy tone: \xe2\x80\x9cit doesn\xe2\x80\x99t seem to\r\ndry me at all.\xe2\x80\x9d\r\n\r\n\xe2\x80\x9cIn that case,\xe2\x80\x9d said the Dodo solemnly, rising to its feet, \xe2\x80\x9cI move\r\nthat the meeting adjourn, for the immediate adoption of more energetic\r\nremedies\xe2\x80\x94\xe2\x80\x9d"
print(len(plain_block))
recons.write(plain_block)
temp_enc_block = bytes([x ^ y for x, y in zip(plain_block, cipher_block)])
for i in range(len(temp_enc_block)):
    if (
        temp_enc_block[i] != 0
        and temp_enc_block[i] != 1
        and temp_enc_block[i] != ord("0")
        and temp_enc_block[i] != ord("1")
    ):
        print(
            i,
            cipher_block[i],
            repr(chr(cipher_block[i])),
            repr(chr(cipher_block[i] ^ 1)),
            repr(chr(cipher_block[i] ^ ord("1"))),
            repr(chr(cipher_block[i] ^ ord("0"))),
        )
        print(plain_block[i:])
        break
print(temp_enc_block)
enc_block_101 = temp_enc_block

j = CHUNK_SIZE * 102
cipher_block = data[j : j + CHUNK_SIZE]
plain_block = b"\r\n\r\n\xe2\x80\x9cSpeak English!\xe2\x80\x9d said the Eaglet. \xe2\x80\x9cI don\xe2\x80\x99t know the meaning of half\r\nthose long words, and, what\xe2\x80\x99s more, I don\xe2\x80\x99t believe you do either!\xe2\x80\x9d And\r\nthe Eaglet bent down its head to hide a smile: some of the other birds\r\ntittered audibly.\r\n\r\n\xe2\x80\x9c"
print(len(plain_block))
recons.write(plain_block)
temp_enc_block = bytes([x ^ y for x, y in zip(plain_block, cipher_block)])
for i in range(len(temp_enc_block)):
    if (
        temp_enc_block[i] != 0
        and temp_enc_block[i] != 1
        and temp_enc_block[i] != 2
        and temp_enc_block[i] != 3
        and temp_enc_block[i] != ord("0")
        and temp_enc_block[i] != ord("1")
        and temp_enc_block[i] != ord("2")
        and temp_enc_block[i] != ord("3")
    ):
        print(
            i,
            cipher_block[i],
            repr(chr(cipher_block[i])),
            repr(chr(cipher_block[i] ^ 1)),
            repr(chr(cipher_block[i] ^ 2)),
            repr(chr(cipher_block[i] ^ 3)),
            repr(chr(cipher_block[i] ^ ord("1"))),
            repr(chr(cipher_block[i] ^ ord("0"))),
            repr(chr(cipher_block[i] ^ ord("2"))),
            repr(chr(cipher_block[i] ^ ord("3"))),
        )
        print(plain_block[i:])
        break
print(temp_enc_block)
enc_block_102 = temp_enc_block

# classify each byte, 100/101/102 -> xyz, xor between xyz and \x00
res = []
for a, b, c, index in zip(enc_block_100, enc_block_101, enc_block_102, range(256)):
    if a == 0 and b == 1 and c == 2:
        res.append("y xor z")
    elif a == 1 and b == 1 and c == 1:
        res.append("x xor y")
    elif a == 1 and b == 0 and c == 3:
        res.append("x xor z")
    elif a == 49 and b == 48 and c == 51: # 103
        res.append("x xor y xor z")
    else:
        res.append("unknown")
        print(index, ":", a, b, c)

for i in range(103, 1000):
    x = str(i // 100).encode()
    y = str((i / 10) % 10).encode()
    z = str(i % 10).encode()
    # 100/101 -> xyz
    last_enc_block = bytearray()
    for type in res:
        if type == "y xor z":
            last_enc_block.append(y[0] ^ z[0])
        elif type == "x xor y":
            last_enc_block.append(x[0] ^ y[0])
        elif type == "x xor z":
            last_enc_block.append(x[0] ^ z[0])
        elif type == "x xor y xor z":
            last_enc_block.append(x[0] ^ y[0] ^ z[0])
        else:
            last_enc_block.append(0)
    j = CHUNK_SIZE * i
    cipher_block = data[j : j + CHUNK_SIZE]
    if len(cipher_block) == 0:
        break
    plain_block = bytes([x ^ y for x, y in zip(last_enc_block, cipher_block)])
    # print(plain_block)
    recons.write(plain_block)
```