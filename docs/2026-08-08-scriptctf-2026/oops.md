# Oops

```
I am from the future! I accidentally forgot to link chall.zip! Surely you can find it and solve it right?
```

Attachment url is `wget https://scriptctf-2026-wave1-randomchars-4f7d3a6b.s3.us-east-1.amazonaws.com/Crypto/Oops/chall.zip` based on the same format as other challenges. `chall.py`:

```python
import random
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

flag = open('flag.txt','rb').read()

random.seed(int(time.time())) # Preserves upto the MINUTE, not seconds ;)
key = random.randbytes(32)

cipher = AES.new(key, AES.MODE_ECB)

enc = cipher.encrypt(pad(flag,16)).hex()

open('enc.txt', 'w').write(enc)
```

We need to recover the time, which can be found by stat-ing the `enc.txt` file:

```shell
$ stat enc.txt
Modify: 2069-11-30 19:39:00.000000000 +0800
```

We then bruteforce the timestamp around that modification time:

```python
import random
import tqdm
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from hashlib import sha256

enc = bytes.fromhex(open("enc.txt", "r").read())

for t in tqdm.trange(3152000000, 3154000000):
    random.seed(t)
    key = random.randbytes(32)

    cipher = AES.new(key, AES.MODE_ECB)
    dec = cipher.decrypt(enc)
    if b"scriptCTF" in dec:
        print(dec)
```

Flag: `scriptCTF{mY_buck37_1s_l34k1ng!}`
