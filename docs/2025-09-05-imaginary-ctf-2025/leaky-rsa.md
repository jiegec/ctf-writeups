# leaky-rsa

```
by wjaaaaaaat
Description

A few of my bits are leaky... but they're not important. That's why they're called the least significant!

nc leaky-rsa.chal.imaginaryctf.org 1337
```

Attachment:

```python
#!/usr/local/bin/python3
import json
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from secrets import randbelow, token_bytes
from hashlib import sha256

with open('flag.txt') as f:
    flag = f.read()

p = getPrime(512)
q = getPrime(512)
n = p * q
e = 65537
d = pow(e, -1, (p-1)*(q-1))

key_m = randbelow(n)
key_c = pow(key_m, e, n)

key = sha256(str(key_m).encode()).digest()[:16]
iv = token_bytes(16)
ct = AES.new(key, AES.MODE_CBC, IV=iv).encrypt(pad(flag.encode(), 16))

print(json.dumps({'n': n, 'c': key_c, 'iv': iv.hex(), 'ct': ct.hex()}))

def get_bit(n, k):
    return (n >> k) % 2

for _ in range(1024):
    idx = randbelow(4)
    print(json.dumps({'idx': idx}))
    try:
        response = json.loads(input())
        c = response['c'] % n
        assert c != key_c
        m = pow(c, d, n)
        b = get_bit(m, idx)
    except (json.JSONDecodeError, TypeError, KeyError, ValueError, AssertionError):
        b = 2
    print(json.dumps({'b': b}))
print(key_m)
```

Initially, I thought it is a RSA parity oracle challenge: we can send `c*(2**i**e)%n` to the server, and know whether `m*(2**i)%n` is even or odd. Then, by binary search we can find `m`. However, we need 1024 such queries to recover `m`, but due to `randbelow(4)`, we can only query 256 times.

Until DeepSeek found the `print(key_m)` on the last line. WTF, the key is given to us. We don't need all those attacks, just wait for the key for decryption.

```python
import json
from pwn import *
from Crypto.Cipher import AES
from hashlib import sha256
import tqdm

# context(log_level="debug")

p = remote(host="leaky-rsa.chal.imaginaryctf.org", port=1337)
# p = process(["python3", "chall.py"])
# skip proof-of-work line
print(p.recvline())
info = json.loads(p.recvline())
for _ in tqdm.tqdm(range(1024)):
    p.recvline()
    p.sendline()
    p.recvline()
key_m = int(p.recvline())
# print(info, key_m)

key = sha256(str(key_m).encode()).digest()[:16]
iv = bytes.fromhex(info['iv'])
ct = bytes.fromhex(info['ct'])
flag = AES.new(key, AES.MODE_CBC, IV=iv).decrypt(ct)
print(flag, key, iv, ct)
```

Flag: `ictf{p13cin9_7h3_b1t5_t0g37her_3f0068c1b9be2547ada52a8020420fb0}`.

Altough it is solved, I am curious whether we can find `key_m` via the 1024 queries...

DeepSeek hinted me about the `print(key_m)` in the source code, here is the full response:

```
To solve this CTF challenge, we need to recover the AES key `key_m` that was encrypted using RSA and then use it to decrypt the flag. The server provides an initial JSON object containing the RSA modulus `n`, the encrypted AES key `key_c`, the initialization vector `iv`, and the ciphertext `ct`. After that, the server enters a loop where it sends an index `idx` and expects a response containing a value `c`. However, if we send an invalid response, the server sets `b` to 2 and continues. After 1024 such interactions, the server prints `key_m` to its output. By leveraging this, we can simply send invalid responses to all queries, receive `key_m` after the loop, and then use it to decrypt the flag.

### Solution Code

import json
import socket
from Crypto.Cipher import AES
from hashlib import sha256

def main():
    # Replace 'server_address' and 'port' with the actual server details
    server_address = 'localhost'
    port = 12345

    # Connect to the server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server_address, port))
    
    # Receive the initial data
    data = s.recv(4096).decode()
    initial = json.loads(data)
    n = initial['n']
    key_c = initial['c']
    iv = bytes.fromhex(initial['iv'])
    ct = bytes.fromhex(initial['ct'])
    
    # Process 1024 queries by sending invalid responses
    for _ in range(1024):
        # Receive the {'idx': idx} message
        data = s.recv(4096).decode()
        # Send an invalid response
        s.send(b'invalid\n')
        # Receive the {'b': 2} response
        data = s.recv(4096).decode()
    
    # After the loop, receive key_m
    data = s.recv(4096).decode().strip()
    try:
        key_m = int(data)
    except:
        # If there is an error, try to find key_m in the data
        # Sometimes there might be extra bytes, so we extract the number
        import re
        match = re.search(r'\d+', data)
        if match:
            key_m = int(match.group())
        else:
            print("Failed to get key_m")
            return
    
    # Compute the AES key from key_m
    key = sha256(str(key_m).encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    flag = cipher.decrypt(ct)
    # Remove padding if necessary
    flag = flag.rstrip(b'\x00')
    print(flag.decode())

if __name__ == '__main__':
    main()

### Explanation
1. **Initial Connection**: The script connects to the server using socket programming and receives the initial JSON data containing `n`, `key_c`, `iv`, and `ct`.
2. **Handling Queries**: For each of the 1024 queries, the script receives the index `idx` from the server, sends an invalid response (`invalid`), and receives the server's response `{'b': 2}`.
3. **Receiving `key_m`**: After processing all queries, the server prints `key_m`, which the script reads from the socket.
4. **Decryption**: The script computes the AES key by hashing `key_m` with SHA-256 and uses it to decrypt the ciphertext `ct` using AES in CBC mode with the provided `iv`.
5. **Output**: The decrypted flag is printed after removing any padding.

This approach efficiently bypasses the need to interact with the queries meaningfully by exploiting the server's behavior of printing `key_m` after 1024 queries, allowing us to decrypt the flag easily.
```
