# java-oracle

```
Consult the Java Oracle Secure Vault — but beware, its predictions leak more than your morning espresso.
nc challs.watctf.org 2013 
```

Attachment:

```python
#!/usr/local/bin/python3
import os
from Crypto.Cipher import AES
import json

N = 16

def load_flag():
    try:
        with open("/flag.txt", "r") as f:
            return f.read().strip()
    except:
        return "fakectf{missing_flag_file}"

def count_blocks(length: int) -> int:
    return (length - 1) // N + 1

def helixlite_padding(message: bytes) -> bytes:
    mlen = len(message)
    blocks = count_blocks(mlen)
    target_len = blocks * N
    if mlen % N == 0:
        target_len += N
    pad_len = target_len - mlen
    return message + bytes([pad_len]) * pad_len

def helixlite_unpad(message: bytes) -> bytes:
    if len(message) < N or len(message) % N != 0:
        raise ValueError("Invalid message length")
    pad_len = message[-1]
    if not (1 <= pad_len <= N):
        raise ValueError("Invalid padding length")
    if message[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding")
    return message[:-pad_len]

def chal():
    FLAG = load_flag()
    k = os.urandom(16)
    m = json.dumps({
        'access_code': FLAG,
        'facility': 'quantum_reactor_z9',
        'clearance': 'alpha'
    }).encode()

    iv = os.urandom(16)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    enc = cipher.encrypt(helixlite_padding(m))
    original = iv + enc

    print(original.hex(), flush=True)
    print("Submit ciphertexts as hex (or type 'quit' to exit):", flush=True)

    while True:
        try:
            line = input("> ").strip()
            if line.lower() in {"quit", "exit", "q"}:
                break

            enc_bytes = bytes.fromhex(line)
            if len(enc_bytes) < 32 or (len(enc_bytes) % 16) != 0:
                print("Invalid data format")
                continue

            if enc_bytes == original:
                print("Valid padding")
                continue

            test_iv, test_ct = enc_bytes[:16], enc_bytes[16:]
            cipher = AES.new(k, AES.MODE_CBC, test_iv)
            pt = cipher.decrypt(test_ct)

            try:
                msg = helixlite_unpad(pt)
                if msg == m:
                    print("Access granted! Flag:", FLAG)
                    break
                else:
                    print("Valid padding")
            except ValueError:
                print("Invalid padding")

        except ValueError:
            print("Parsing error: invalid hexadecimal")
        except KeyboardInterrupt:
            break
        except Exception:
            print("Critical error")

if __name__ == "__main__":
    chal()
```

A typical padding oralce attack. You can refer to my previous [writeup](../2025-09-04-nullcon-berlin-hackim-2025-ctf/decryption-execution-service.md) to see how it works.

Attach script:

```python
from pwn import *

# context(log_level="debug")

p = process(["python3", "challenge.py"])
# p = remote(host="challs.watctf.org", port=2013)

original = bytes.fromhex(p.recvline().decode())
print(len(original))

plain = bytearray()
for part in range(16, len(original), 16):
    iv = [0] * 16
    known = [0] * 16
    msg = original[part : part + 16]
    # padding oracle attack
    for i in range(1, 17):
        good = []
        for j in range(1, i):
            iv[16 - j] = known[16 - j] ^ i
        for ch in range(256):
            iv[16 - i] = ch
            p.recvuntil(b"> ")
            p.sendline((bytes(iv) + msg).hex().encode())
            res = p.recvline()
            if b"Valid padding" in res:
                good.append(ch)
        if len(good) == 1:
            known[16 - i] = i ^ good[0]
        else:
            print(good)
            assert False
    plain += bytes([a ^ b for a, b in zip(original[part - 16 : part], known)])
    print(plain)
```

Since the flag is embedded in the plain text, there is no need to create a fake ciphertext that decrypts to the same plain text. After running the attack script on a VPS near to the server, we can get the flag: `watctf{quantum_helix_padding_oracle}`.
