# EaaS

```
Email as a Service! Have fun...
```

Provided source code:

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import random
email=''
flag=open('flag.txt').read()
has_flag=False
sent=False
key = os.urandom(32)
iv = os.urandom(16)
encrypt = AES.new(key, AES.MODE_CBC,iv)
decrypt = AES.new(key, AES.MODE_CBC,iv)

def send_email(recipient):
    global has_flag
    if recipient.count(b',')>0:
        recipients=recipient.split(b',')
    else:
        recipients=recipient
    for i in recipients:
        if i == email.encode():
            has_flag = True

for i in range(10):
    email += random.choice('abcdefghijklmnopqrstuvwxyz')
email+='@notscript.sorcerer'

print(f"Welcome to Email as a Service!\nYour Email is: {email}\n")
password=bytes.fromhex(input("Enter secure password (in hex): "))

assert not len(password) % 16
assert b"@script.sorcerer" not in password
assert email.encode() not in password

encrypted_pass = encrypt.encrypt(password)
print("Please use this key for future login: " + encrypted_pass.hex())

while True:
    choice = int(input("Enter your choice: "))
    print(f"[1] Check for new messages\n[2] Get flag")

    if choice == 1:
        if has_flag:
            print(f"New email!\nFrom: scriptsorcerers@script.sorcerer\nBody: {flag}")
        else:
            print("No new emails!")

    elif choice == 2:
        if sent:
            exit(0)
        sent=True
        user_email_encrypted = bytes.fromhex(input("Enter encrypted email (in hex): ").strip())
        if len(user_email_encrypted) % 16 != 0:
            print("Email length needs to be a multiple of 16!")
            exit(0)
        user_email = decrypt.decrypt(user_email_encrypted)
        if user_email[-16:] != b"@script.sorcerer":
            print("You are not part of ScriptSorcerers!")
            exit(0)

        send_email(user_email)
        print("Email sent!")
```

Effectively, we need to:

1. choose a plaintext, not containing `@script.sorcerer` or `xxxxxxxxxx@notscript.sorcerer`
2. get its ciphertext
3. give a new ciphertext
4. decrypts to something containing `,xxxxxxxxxx@notscript.sorcerer,` and ending with `@script.sorcerer`

Do chosen plain text attack twice:

First, we select five 16-byte plaintext blocks called `P1-P5`.

Second, encrypt it via AES-CBC, got five ciphertext blocks called `C1-C5`:

```python
C1 = AESEnc(Key, P1 xor IV)
C2 = AESEnc(Key, P2 xor C1)
C3 = AESEnc(Key, P3 xor C2)
C4 = AESEnc(Key, P4 xor C3)
C5 = AESEnc(Key, P5 xor C4)
```

Third, chosse five ciphertext blocks called `c1-c5` that decrypt to five plaintext blocks called `p1-p5`:

```python
p1 = AESDec(Key, c1) xor IV
p2 = AESDec(Key, c2) xor c1
p3 = AESDec(Key, c3) xor c2
p4 = AESDec(Key, c4) xor c3
p5 = AESDec(Key, c5) xor c4
```

We need `p1-p5` concatenated to satisfy the requirement, so we set:

```
p2 = ",,xxxxxxxxxx@not"
p3 = "script.sorcerer,"
p5 = "@script.sorcerer"
```

which can be achieved by setting:

```
P3 = "script.sorcerer,"
c1 = p2 xor P2 xor C1
c2 = C2
c3 = C3
c4 = p5 xor P5 xor C4
c5 = C5
```

verify:

```
p2 = AESDec(Key, c2) xor c1 = AESDec(Key, C2) = AESDec(Key, AESEnc(Key, P2 xor C1)) xor c1 = P2 xor C1 xor c1 = P2 xor C1 xor p2 xor P2 xor C1 = p2
p5 = AESDec(Key, c5) xor c4 = AESDec(Key, C5) xor c4 = AESDec(Key, AESEnc(Key, P5 xor C4)) xor c4 = P5 xor C4 xor c4 = P5 xor C4 xor p5 xor P5 xor C4 = p5
```

Code:

```python
from pwn import *

context(log_level="debug")

#p = process("./server.py")
p = remote("play.scriptsorcerers.xyz", 10346)
email = p.recvuntil("secure password").splitlines()[1].split()[3].strip()
print("email", email)
expected = f",,{email.decode()},".encode()
expected1 = expected[:16]
expected2 = expected[16:]
print(expected1)
print(expected2)
# AAAA AAAA expected2 AAAA AAAA
# CBC encrypt
a_block = ("A" * 16).encode()
p.sendline((a_block + a_block + expected2 + a_block + a_block).hex())
# encrypted
# block0 block1 block2 block3 block4
enc = bytes.fromhex(p.recvuntil("choice").splitlines()[0].split()[-1].decode())
block0 = enc[0:16]
block1 = enc[16:32]
block2 = enc[32:48]
block3 = enc[48:64]
block4 = enc[64:80]
# before xor
raw1 = xor(block0, a_block)
xorred1 = xor(expected1, raw1)
expected3 = "@script.sorcerer".encode()
raw2 = xor(block3, a_block)
xorred2 = xor(expected3, raw2)
# becomes
# xxxx expected1 expected2 xxxx expected3

p.sendline("2")
p.sendline((xorred1 + block1 + block2 + xorred2 + block4).hex().encode())
p.sendline("1")

p.interactive()
```

Get flag:

```
New email!
From: scriptsorcerers@script.sorcerer
Body: scriptCTF{CBC_1s_s3cur3_r1ght?_ff00a87ab512}
```
