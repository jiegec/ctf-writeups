# Tampering Detection System

Co-authors: @JOHNKRAM @Rosayxy

Attachment:

```python
#!/usr/local/bin/python
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

try:
    with open("/flag.txt", "rb") as f:
        FLAG = f.read()
except FileNotFoundError:
    FLAG = b"FLAG{******** REDACTED ********}"

def encrypt(plaintext: bytes, key: bytes, nonce: bytes, associated_data: bytes = b""):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(associated_data)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag

def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes, associated_data: bytes = b""):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(associated_data)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

def query(ciphertext: bytes, aad: bytes, key: bytes, tag: bytes, nonce: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try: 
        cipher.update(aad)
        cipher.decrypt_and_verify(ciphertext, tag)
        return True
    except:
        return False

nonce = get_random_bytes(12)
key = get_random_bytes(32)

flag_ciphertext, flag_tag = encrypt(FLAG, key, nonce, b"")
print("flag ciphertext: ", base64.b64encode(flag_ciphertext).decode())
print("flag tag: ", base64.b64encode(flag_tag).decode())

user_plaintext = input("your_text1:")
ciphertext, tag = encrypt(user_plaintext.encode(), key, nonce, b"")
print("tag1: ", base64.b64encode(tag).decode())

user_plaintext = input("your_text2:")
ciphertext, tag = encrypt(user_plaintext.encode(), key, nonce, b"")
print("tag2: ", base64.b64encode(tag).decode())

while True:
    length = int(input("length:"))
    aad = base64.b64decode(input("aad: "))
    print(query(ciphertext[:length], aad, key, tag, nonce))
```

The server reuses nonce for AES-GCM mode, which is vulnerable. We deployed the attack according to [AES-GCM and breaking it on nonce reuse](https://frereit.de/aes_gcm/):

1. We obtain two pairs of (plain, tag): (plain1, tag1) and (plain2, tag2), and because they are encrypted using the same key and nonce, so the cipher texts satisfy: `cipher1 xor cipher2 == plain1 xor plain2` when they have the same length (pointed out by @JOHNKRAM).
2. Given the two known pairs, we can create a polynomial of H by xor-ing the computation of tag1 and tag2. We can find its roots using SageMath. See the article above for a detailed description.
3. After solving H, we conduct an attack similar to CBC Padding Oracle Attack, but from the front: from length of one to flag full length, enumerate each byte and compute the authentication data that computes to the same tag. If it replys with True, we found the correct byte.

Attack script:

```python
from pwn import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor
import base64
import galois

GF = galois.GF(2**128, irreducible_poly="x^128 + x^7 + x^2 + x + 1")


def to_gf(num):
    # from LSB to MSB
    ret = GF(0)
    assert num <= 2**128
    for i in range(128):
        if num & (1 << i) != 0:
            ret += GF(2 ** (127 - i))
    return ret


def from_gf(gf):
    # from LSB to MSB
    num = int(gf)
    ret = 0
    for i in range(128):
        if num & (1 << i) != 0:
            ret += 2 ** (127 - i)
    return ret


# context(log_level="DEBUG")


def gcm_nonce_reuse(cipher1: bytes, tag1: bytes, cipher2: bytes, tag2: bytes) -> bytes:
    """
    AES GCM Nonce Reuse attack, learned from https://frereit.de/aes_gcm/,
    given two pairs of known (cipher, tag) encrypted using the same key and associated data,
    recover H = AES-ECB-Encrypt(key, b"\x00" * 16),
    because cipher1 xor cipher2 == plain1 xor plain2, plaintext can be used instead

    Args:
        cipher1 (bytes): the first ciphertext
        tag1 (bytes): the first tag
        cipher2 (bytes): the second ciphertext
        tag2 (bytes): the second tag

    Returns:
        H: the array of recovered H
    """

    from sage.all import GF, PolynomialRing

    # use sage to solve polynomials on GF(2^128)
    F = GF(2)["a"]
    (a,) = F._first_ngens(1)
    F = GF(2**128, modulus=a**128 + a**7 + a**2 + a + 1, names=("x",))
    (x,) = F._first_ngens(1)
    R = PolynomialRing(F, names=("H",))
    (H,) = R._first_ngens(1)

    # construct polynomial based on two tuples
    polys = []
    for cipher, tag in [(cipher1, tag1), (cipher2, tag2)]:
        poly = 0

        blocks = []
        # plaintext part
        for i in range((len(cipher) + 15) // 16):
            part = cipher[i * 16 : (i + 1) * 16]
            if len(part) < 16:
                part += b"\x00" * (16 - len(part))
            blocks.append(part)
        # len(plain) part
        blocks.append(long_to_bytes(len(cipher) * 8, 16))

        # compute poly for blocks
        for block in blocks:
            temp = 0
            for i in range(128):
                if bytes_to_long(block) & (1 << i) != 0:
                    temp += x ** (127 - i)

            poly = poly * H + temp

        # compute poly for tag part
        temp = 0
        for i in range(128):
            if bytes_to_long(tag) & (1 << i) != 0:
                temp += x ** (127 - i)
        poly = poly * H + temp
        polys.append(poly)

    roots = (polys[0] + polys[1]).roots()
    res = []
    for root in roots:
        coefs = root[0].list()
        H = 0
        for i in range(128):
            if coefs[i] != 0:
                H += 2 ** (127 - i)
        res.append(long_to_bytes(H))
    return res

p = process(["python3", "./server.py"])
# step 1: recover H
p.recvuntil(b"flag ciphertext: ")
flag_cipher = base64.b64decode(p.recvline().decode())
p.recvuntil(b"flag tag: ")
flag_tag = base64.b64decode(p.recvline().decode())

plain_len = 128
plain1 = b"A" * plain_len
p.recvuntil(b"your_text1:")
p.sendline(plain1)
p.recvuntil(b"tag1: ")
tag1 = base64.b64decode(p.recvline().decode())

plain2 = b"B" * plain_len
p.recvuntil(b"your_text2:")
p.sendline(plain2)
p.recvuntil(b"tag2: ")
tag2 = base64.b64decode(p.recvline().decode())

# plain1 xor plain2 == cipher1 xor cipher2
res = gcm_nonce_reuse(plain1, tag1, plain2, tag2)

for H in res:
    H_gf = to_gf(bytes_to_long(H))
    H_gf_inverse = H_gf**-1

    # compute J0_enc
    T = 0
    for i in range((len(flag_cipher) + 15) // 16):
        part = flag_cipher[i * 16 : (i + 1) * 16]

        # update
        T = T * H_gf + to_gf(bytes_to_long(part) * (256 ** (16 - len(part))))

    L = len(flag_cipher) * 8
    T = T * H_gf + to_gf(L)
    T = T * H_gf + to_gf(bytes_to_long(flag_tag))
    J0_enc = T

    # enumerate cipher2
    cipher2 = bytearray([0] * plain_len)
    for length in range(1, 64):
        for b in range(256):
            cipher2[length-1] = b
            cur_cipher2 = cipher2[:length]

            T = 0
            blocks = (len(cur_cipher2) + 15) // 16
            for i in range(blocks):
                part = cur_cipher2[i * 16 : (i + 1) * 16]

                # update
                T = T * H_gf + to_gf(bytes_to_long(part) * (256 ** (16 - len(part))))

            L = len(cur_cipher2) * 8 + 16 * 8 * (2 ** 64)
            T = T * H_gf + to_gf(L)
            T = T * H_gf + J0_enc + to_gf(bytes_to_long(tag2))
            # found required aad to match tag
            aad = T * H_gf_inverse ** (2+blocks)
            # correct guess?
            p.recvuntil(b"length:")
            p.sendline(str(length).encode())
            p.recvuntil(b"aad: ")
            aad_data = long_to_bytes(from_gf(aad), 16)
            p.sendline(base64.b64encode(aad_data))
            resp = p.recvline()
            if resp == b"True\n":
                print("Found", b)
                # recover plain using the current cipher
                l = min(len(flag_cipher), len(plain2))
                temp = strxor(bytes(cipher2[:l]), flag_cipher[:l])
                temp = strxor(temp, plain2[:l])
                print("flag", temp)
                break
            elif resp != b"False\n":
                assert False, resp
```

## Alternative solution

An alternative solution attacks from the back to the front, which is more complex but does not require `flag_tag`:

1. After solving H, we conduct an attack similar to CBC Padding Oracle Attack from the back: shorten the length one by one, enumerate the truncated byte, and compute the authentication data that computes to the same tag. By changing the length of the plaintext, we can recover different parts of the flag (pointed out by @JOHNKRAM).
2. We can recover most of the flag now (except byte at 0, 16, 32). The rest can be simply bruteforced, due to the small space. Given the flag, we can recover `AES-ECB-Encrypt(key, nonce || 1)` and verify if tag1 can be computed correctly.

Attack script (modified to match server's flag length of 42 bytes):

```python
from pwn import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor
import base64
import galois

GF = galois.GF(2**128, irreducible_poly="x^128 + x^7 + x^2 + x + 1")


def to_gf(num):
    # from LSB to MSB
    ret = GF(0)
    assert num <= 2**128
    for i in range(128):
        if num & (1 << i) != 0:
            ret += GF(2 ** (127 - i))
    return ret


def from_gf(gf):
    # from LSB to MSB
    num = int(gf)
    ret = 0
    for i in range(128):
        if num & (1 << i) != 0:
            ret += 2 ** (127 - i)
    return ret


# context(log_level="DEBUG")


def gcm_nonce_reuse(cipher1: bytes, tag1: bytes, cipher2: bytes, tag2: bytes) -> bytes:
    """
    AES GCM Nonce Reuse attack, learned from https://frereit.de/aes_gcm/,
    given two pairs of known (cipher, tag) encrypted using the same key and associated data,
    recover H = AES-ECB-Encrypt(key, b"\x00" * 16),
    because cipher1 xor cipher2 == plain1 xor plain2, plaintext can be used instead

    Args:
        cipher1 (bytes): the first ciphertext
        tag1 (bytes): the first tag
        cipher2 (bytes): the second ciphertext
        tag2 (bytes): the second tag

    Returns:
        H: the array of recovered H
    """

    from sage.all import GF, PolynomialRing

    # use sage to solve polynomials on GF(2^128)
    F = GF(2)["a"]
    (a,) = F._first_ngens(1)
    F = GF(2**128, modulus=a**128 + a**7 + a**2 + a + 1, names=("x",))
    (x,) = F._first_ngens(1)
    R = PolynomialRing(F, names=("H",))
    (H,) = R._first_ngens(1)

    # construct polynomial based on two tuples
    polys = []
    for cipher, tag in [(cipher1, tag1), (cipher2, tag2)]:
        poly = 0

        blocks = []
        # plaintext part
        for i in range((len(cipher) + 15) // 16):
            part = cipher[i * 16 : (i + 1) * 16]
            if len(part) < 16:
                part += b"\x00" * (16 - len(part))
            blocks.append(part)
        # len(plain) part
        blocks.append(long_to_bytes(len(cipher) * 8, 16))

        # compute poly for blocks
        for block in blocks:
            temp = 0
            for i in range(128):
                if bytes_to_long(block) & (1 << i) != 0:
                    temp += x ** (127 - i)

            poly = poly * H + temp

        # compute poly for tag part
        temp = 0
        for i in range(128):
            if bytes_to_long(tag) & (1 << i) != 0:
                temp += x ** (127 - i)
        poly = poly * H + temp
        polys.append(poly)

    roots = (polys[0] + polys[1]).roots()
    res = []
    for root in roots:
        coefs = root[0].list()
        H = 0
        for i in range(128):
            if coefs[i] != 0:
                H += 2 ** (127 - i)
        res.append(long_to_bytes(H))
    return res


flag_parts = []
for plain_len in [16, 32, 48]:
    p = process(["python3", "./server.py"])
    # step 1: recover H
    p.recvuntil(b"flag ciphertext: ")
    flag_cipher = base64.b64decode(p.recvline().decode())
    p.recvuntil(b"flag tag: ")
    flag_tag = base64.b64decode(p.recvline().decode())

    plain1 = b"A" * plain_len
    p.recvuntil(b"your_text1:")
    p.sendline(plain1)
    p.recvuntil(b"tag1: ")
    tag1 = base64.b64decode(p.recvline().decode())

    plain2 = b"B" * plain_len
    p.recvuntil(b"your_text2:")
    p.sendline(plain2)
    p.recvuntil(b"tag2: ")
    tag2 = base64.b64decode(p.recvline().decode())

    # plain1 xor plain2 == cipher1 xor cipher2
    res = gcm_nonce_reuse(plain1, tag1, plain2, tag2)
    print("Got", len(res), "H")
    for H in res:
        print(H)
        H_gf = to_gf(bytes_to_long(H))
        H_gf_inverse = H_gf**-1

        # for all possible ciphertext, compute corresponding AAD
        cipher = [0] * len(plain2)
        # from right
        for i in range(16):
            # enumerate the next byte
            good = False
            for b in range(256):
                length = len(plain2) - i - 1
                cipher[length] = b
                # compute contribution of the truncated bytes
                part = cipher[length - 1 :]
                contribution_b = to_gf(bytes_to_long(bytes(part))) * H_gf**2
                # compute contribution of len(CT)
                contribution_len_ct = (
                    to_gf(len(plain2) * 8) + to_gf(length * 8)
                ) * H_gf
                # compute contribution of len(AAD)
                contribution_len_aad = to_gf(128 * (2**64)) * H_gf
                blocks = len(plain2) // 16
                aad = (
                    contribution_b + contribution_len_ct + contribution_len_aad
                ) * H_gf_inverse ** (2 + blocks)

                # cancel out
                contribution = (
                    contribution_b
                    + contribution_len_ct
                    + contribution_len_aad
                    + aad * (H_gf) ** (2 + blocks)
                )
                assert contribution == 0

                # correct guess?
                p.recvuntil(b"length:")
                p.sendline(str(length).encode())
                p.recvuntil(b"aad: ")
                aad_data = long_to_bytes(from_gf(aad), 16)
                p.sendline(base64.b64encode(aad_data))
                resp = p.recvline()
                if resp == b"True\n":
                    print("Found", b)
                    good = True
                    break
                elif resp != b"False\n":
                    assert False, resp
            if not good:
                print("Bad H")
                break
            cipher[length] = b
            print("cipher", bytes(cipher))

            # recover plain using the current cipher
            l = min(len(flag_cipher), len(plain2))
            temp = strxor(bytes(cipher[:l]), flag_cipher[:l])
            temp = strxor(temp, plain2[:l])
            print("flag", temp)

        if i >= 15:
            flag_parts.append(temp)
            print("Done", i)
            break

flag = flag_parts[0] + flag_parts[1][16:] + flag_parts[2][32:]
print(flag)

# find flag[0, 16, 32]

p = process(["python3", "./server.py"])
# step 1: recover H
p.recvuntil(b"flag ciphertext: ")
flag_cipher = base64.b64decode(p.recvline().decode())
p.recvuntil(b"flag tag: ")
flag_tag = base64.b64decode(p.recvline().decode())

plain_len = len(flag)
plain1 = b"A" * plain_len
p.recvuntil(b"your_text1:")
p.sendline(plain1)
p.recvuntil(b"tag1: ")
tag1 = base64.b64decode(p.recvline().decode())

plain2 = b"B" * plain_len
p.recvuntil(b"your_text2:")
p.sendline(plain2)
p.recvuntil(b"tag2: ")
tag2 = base64.b64decode(p.recvline().decode())

# plain1 xor plain2 == cipher1 xor cipher2
res = gcm_nonce_reuse(plain1, tag1, plain2, tag2)

for H in res:
    H_gf = to_gf(bytes_to_long(H))

    # compute J0_enc
    T = 0
    for i in range((len(flag) + 15) // 16):
        part = flag_cipher[i * 16 : (i + 1) * 16]

        # update
        T = T * H_gf + to_gf(bytes_to_long(part) * (256 ** (16 - len(part))))

    L = len(flag) * 8
    T = T * H_gf + to_gf(L)
    T = T * H_gf + to_gf(bytes_to_long(flag_tag))
    J0_enc = T

    for ch1 in string.printable:
        for ch2 in string.printable:
            # guess flag
            cur_flag = bytearray(flag)
            cur_flag[0] = ord("F")  # assume flag starting with F
            cur_flag[16] = ord(ch1)
            cur_flag[32] = ord(ch2)

            # compute cipher2
            temp = strxor(flag_cipher, cur_flag)
            cipher2 = strxor(temp, plain2)

            # verify tag2
            T = 0
            for i in range((len(plain2) + 15) // 16):
                part = cipher2[i * 16 : (i + 1) * 16]

                # update
                T = T * H_gf + to_gf(bytes_to_long(part) * (256 ** (16 - len(part))))

            L = len(plain2) * 8
            T = T * H_gf + to_gf(L)
            T = T * H_gf + J0_enc
            if T == from_gf(bytes_to_long(tag2)):
                print("Found flag", bytes(cur_flag))
                exit(0)
```

Good to read: [AES GCM and AES GCM-SIV mode](https://blog.malosdaf.me/posts/aes-gcm-and-aes-gcm-siv-mode/).
