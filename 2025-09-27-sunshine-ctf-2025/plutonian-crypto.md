# Plutonian Crypto

```
One of our deep space listening stations has been receiving a repeating message that appears to be coming from Pluto. It is encrypted with some sort of cipher but our best scientists have at least been able to decrypt the first part of the message, "Greetings, Earthlings."

See if you are able to somehow break their encryption and find out what the message is!
nc chal.sunshinectf.games 25403 
```

Attachment:

```python
#!/usr/bin/env python3
import sys
import time
from binascii import hexlify
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes
from ctf_secrets import MESSAGE

KEY = get_random_bytes(16)
NONCE = get_random_bytes(8)

WELCOME = '''
     ,-.
    /   \\ 
   :     \\      ....*
   | . .- \\-----00''
   : . ..' \\''//
    \\ .  .  \\/
     \\ . ' . NASA Deep Space Listening Posts
  , . \\       \\     ~ Est. 1969 ~
,|,. -.\\       \\
    '.|| `-...__..-
      | | "We're always listening to you!"
     |__|
    /||\\\\
    //||\\\\
   // || \\\\
__//__||__\\\\__
'--------------'
'''
 
def main():
 
    # Print ASCII art and intro
    sys.stdout.write(WELCOME)
    sys.stdout.flush()
    time.sleep(0.5)
    
    sys.stdout.write("\nConnecting to remote station")
    sys.stdout.flush()
    
    for i in range(5):
        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(0.5)
    
    sys.stdout.write("\n\n== BEGINNING TRANSMISSION ==\n\n")
    sys.stdout.flush()

    C = 0
    while True:
        ctr = Counter.new(64, prefix=NONCE, initial_value=C, little_endian=False)
        cipher = AES.new(KEY, AES.MODE_CTR, counter=ctr)
        ct = cipher.encrypt(MESSAGE)
        sys.stdout.write("%s\n" % hexlify(ct).decode())
        sys.stdout.flush()
        C += 1
        time.sleep(0.5)

if __name__ == "__main__":
    main()
```

It uses AES-CTR encryption, but nonce is reused. Therefore, give the block 0 of plain text, we known the block 0 of plain text xor `AES-Enc(key, nonce || i)` from the first hex received, and block i of plain text xor `AES-Enc(key, nonce || i)` from a later hex received. we can recover block i of plaintext by xor to cancel the `AES-Enc(key, nonce || i)` out. Attack:

```python
# get enough data from:
# nc chal.sunshinectf.games 25403 > plutonian.txt
lines = open("plutonian.txt", "r", encoding="utf-8").readlines()
plain0 = b"Greetings, Earthlings."

ctr0_data = bytes.fromhex(lines[24])
print(len(ctr0_data))

# find plain i by:
# plain0 xor (plain0 xor ctri) xor (plaini xor ctri)
plain = bytearray()
for i, line in enumerate(lines[25:]):
    data = bytes.fromhex(line)
    recovered = bytes(
        [
            x ^ y ^ z
            for x, y, z in zip(
                plain0, data[0:16], ctr0_data[(i + 1) * 16 : (i + 2) * 16]
            )
        ]
    )
    plain += recovered
print(plain)
```

Flag: `sun{n3v3r_c0unt_0ut_th3_p1ut0ni4ns}`.
