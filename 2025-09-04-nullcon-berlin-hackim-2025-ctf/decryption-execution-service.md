#  decryption execution service

```
I have this online service, that executes my commands. But only with the correct key can you craft a proper command. Everything else gets rejected.
nc 52.59.124.14 5102
```

The attachment provides the server implementation:

```python
from Crypto.Cipher import AES
import os
import json

class PaddingError(Exception):
	pass

flag = open('flag.txt','r').read().strip()
key = os.urandom(16)

def unpad(msg : bytes):
	pad_byte = msg[-1]
	if pad_byte == 0 or pad_byte > 16: raise PaddingError
	for i in range(1, pad_byte+1):
		if msg[-i] != pad_byte: raise PaddingError
	return msg[:-pad_byte]

def decrypt(cipher : bytes):
	if len(cipher) % 16 > 0: raise PaddingError
	decrypter = AES.new(key, AES.MODE_CBC, iv = cipher[:16])
	msg_raw = decrypter.decrypt(cipher[16:])
	return unpad(msg_raw)

if __name__ == '__main__':
	while True:
		try:
			cipher_hex = input('input cipher (hex): ')
			if cipher_hex == 'exit': break
			cipher = decrypt(bytes.fromhex(cipher_hex))
			json_token = json.loads(cipher.decode())
			eval(json_token['command'])
		except PaddingError:
			print('invalid padding')
		except (json.JSONDecodeError, UnicodeDecodeError):
			print('no valid json')
		except:
			print('something else went wrong')
```

It is prone to padding oracle attack: we can know if the padding is invalid or not. Through padding oracle attack, we can find the plaintext given ciphertext. I made a video on [padding oracle attack in Chinese](https://www.bilibili.com/video/BV1au4y1m7KQ/) previously.

Since we want to read the flag out, we want the decrypted string to be `{"command":"print(flag)"}` with padding added. It needs two AES blocks to save it. So:

1. let expected2 = `{"command":"prin`, expected1 = `t(flag)"}\x07\x07\x07\x07\x07\x07\x07`
2. find plaintext according to msg1 by padding oracle attack: `known1 = AES-ECB-Decrypt(key, msg1)`, where msg1 can be anything, e.g. all zeros
3. now, we want the second block to be decrypted to expected1, so the first block should be: `msg2 = known1 xor expected1`
4. find plaintext according to msg2 by padding oracle attack: `known2 = AES-ECB-Decrypt(key, msg2)`
5. make the first block to be decrypted to expected2: `iv = known2 xor expected2`

Concat them together:

```
AES-CBC-Decrypt(key, iv, msg2 || msg1)
= (iv xor AES-ECB-Decrypt(key, msg2)) || (msg2 xor AES-ECB-Decrypt(key, msg1))
= (iv xor known2) || (msg2 xor known1)
= (expected2) || (expected1)
= expected
```

Attack code:

```python
from pwn import *

# context(log_level="debug")

# p = process(["python3", "chall.py"])
p = remote(host="52.59.124.14", port=5102)


def find(msg):
    iv = [0] * 16
    known = [0] * 16
    # padding oracle attack
    for i in range(1, 17):
        good = []
        for j in range(1, i):
            iv[16 - j] = known[16 - j] ^ i
        for ch in range(256):
            iv[16 - i] = ch
            p.recvuntil("cipher")
            p.sendline(bytes(iv + msg).hex())
            res = p.recvline()
            if b"no valid json" in res:
                good.append(ch)
        if len(good) == 1:
            known[16 - i] = i ^ good[0]
        else:
            print(good)
            assert False
    return known


# msg1 encrypts to known1
msg1 = [0] * 16
known1 = find(msg1)

expected = bytearray(b'{"command":"print(flag)"}')
# add padding
padding = 16 - len(expected) % 16
for i in range(padding):
    expected.append(padding)

# msg2 encrypts to known2
msg2 = [expected[16 + i] ^ known1[i] for i in range(16)]
known2 = find(msg2)

iv = [expected[i] ^ known2[i] for i in range(16)]
p.recvuntil("cipher")
p.sendline(bytes(iv + msg2 + msg1).hex())
p.interactive()
```

I run it in an AWS instance in eu-central-1 region to make it run faster.

Get flag: `ENO{the_oracle_can_also_create_messages_as_desired}`.
