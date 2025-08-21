# Secure Server 2

```
This time, the server is even more secure, but did it actually receive the secret? Simple brute-force won't work!
```

Provided files:

```python
# server.py
import os
from Crypto.Cipher import AES
print("With the Secure Server 2, sharing secrets is safer than ever! We now support double encryption with AES!")
enc = bytes.fromhex(input("Enter the secret, encrypted twice with your keys (in hex): ").strip())
# Our proprietary key generation method, used by the server and John Doe himself!
k3 = b'BB' # Obviously not the actual key
k4 = b'B}' # Obviously not the actual key
# flag = secret_message + k1 + k2 + k3 + k4 (where each key is 2 bytes)
# In this case: scriptCTF{testtesttesttesttest!_AAAABBB}
keys = [k3,k4]
final_keys = []
for key in keys:
    assert len(key) == 2 # 2 byte key into binary
    final_keys.append(bin(key[0])[2:].zfill(8)+bin(key[1])[2:].zfill(8))

cipher = AES.new(final_keys[0].encode(), mode=AES.MODE_ECB)
cipher2 = AES.new(final_keys[1].encode(), mode=AES.MODE_ECB)
enc2 = cipher2.encrypt(cipher.encrypt(enc)).hex()
print(f"Quadriple encrypted secret (in hex): {enc2}")
dec = bytes.fromhex(input("Decrypt the above with your keys again (in hex): ").strip())
secret = cipher.decrypt(cipher2.decrypt(dec))
print("Secret received!")
```

```python
# johndoe.py
from Crypto.Cipher import AES
k1 = b'AA' # Obviously not the actual key
k2 = b'AA' # Obviously not the actual key
message = b'scriptCTF{testtesttesttesttest!_' # Obviously not the actual flag
keys = [k1,k2]
final_keys = []
for key in keys:
    assert len(key) == 2 # 2 byte key into binary
    final_keys.append(bin(key[0])[2:].zfill(8)+bin(key[1])[2:].zfill(8))


cipher = AES.new(final_keys[0].encode(), mode=AES.MODE_ECB)
cipher2 = AES.new(final_keys[1].encode(), mode=AES.MODE_ECB)
enc2 = cipher2.encrypt(cipher.encrypt(message)).hex()

print(enc2)

to_dec = bytes.fromhex(input("Dec: ").strip())

secret = cipher.decrypt(cipher2.decrypt(to_dec))

print(secret.hex())
```

Extracted from pcap:

```
With the Secure Server 2, sharing secrets is safer than ever! We now support double encryption with AES!
Enter the secret, encrypted twice with your keys (in hex): 
19574ac010cc9866e733adc616065e6c019d85dd0b46e5c2190c31209fc57727

Quadriple encrypted secret (in hex): 0239bcea627d0ff4285a9e114b660ec0e97f65042a8ad209c35a091319541837
Decrypt the above with your keys again (in hex): 
4b3d1613610143db984be05ef6f37b31790ad420d28e562ad105c7992882ff34

Secret received!
```

Therefore:

1. enc(enc(secret_message, k1), k2) == "19574ac010cc9866e733adc616065e6c019d85dd0b46e5c2190c31209fc57727"
2. enc(enc("19574ac010cc9866e733adc616065e6c019d85dd0b46e5c2190c31209fc57727", k3), k4) == "0239bcea627d0ff4285a9e114b660ec0e97f65042a8ad209c35a091319541837"
3. dec(dec("0239bcea627d0ff4285a9e114b660ec0e97f65042a8ad209c35a091319541837", k2), k1) == "4b3d1613610143db984be05ef6f37b31790ad420d28e562ad105c7992882ff34"

Bruteforce k3, k4:

```python
import os
from Crypto.Cipher import AES

enc = bytes.fromhex("19574ac010cc9866e733adc616065e6c019d85dd0b46e5c2190c31209fc57727")
for t3_1 in range(0x20, 0x7F):
    for t3_2 in range(0x20, 0x7F):
        k3 = bytes([t3_1, t3_2])
        for t4_1 in range(0x20, 0x7F):
            k4 = bytes([t4_1, ord(b"}")])
            keys = [k3, k4]
            final_keys = []
            for key in keys:
                assert len(key) == 2  # 2 byte key into binary
                final_keys.append(bin(key[0])[2:].zfill(8) + bin(key[1])[2:].zfill(8))

            cipher = AES.new(final_keys[0].encode(), mode=AES.MODE_ECB)
            cipher2 = AES.new(final_keys[1].encode(), mode=AES.MODE_ECB)
            enc2 = cipher2.encrypt(cipher.encrypt(enc)).hex()
            if (
                enc2
                == "0239bcea627d0ff4285a9e114b660ec0e97f65042a8ad209c35a091319541837"
            ):
                print(k3, k4)
                exit(0)
```

Get k3 = "f8", k4 = "d}".

Bruteforce k1, k2:

```python
import os
from Crypto.Cipher import AES

secret = bytes.fromhex(
    "0239bcea627d0ff4285a9e114b660ec0e97f65042a8ad209c35a091319541837"
)

for t1_1 in range(0x20, 0x7F):
    for t1_2 in range(0x20, 0x7F):
        k1 = bytes([t1_1, t1_2])
        print(k1)
        for t2_1 in range(0x20, 0x7F):
            for t2_2 in range(0x20, 0x7F):
                k2 = bytes([t2_1, t2_2])
                keys = [k1, k2]
                final_keys = []
                for key in keys:
                    assert len(key) == 2  # 2 byte key into binary
                    final_keys.append(
                        bin(key[0])[2:].zfill(8) + bin(key[1])[2:].zfill(8)
                    )
                cipher = AES.new(final_keys[0].encode(), mode=AES.MODE_ECB)
                cipher2 = AES.new(final_keys[1].encode(), mode=AES.MODE_ECB)
                enc2 = cipher.decrypt(cipher2.decrypt(secret)).hex()
                if (
                    enc2
                    == "4b3d1613610143db984be05ef6f37b31790ad420d28e562ad105c7992882ff34"
                ):
                    print(k1, k2)
                    exit(0)
```

Get k1 = "e4", k4 = "b3".

Decrypt secret message:

```python
import os
from Crypto.Cipher import AES

enc = bytes.fromhex("19574ac010cc9866e733adc616065e6c019d85dd0b46e5c2190c31209fc57727")
k1 = b"e4"
k2 = b"b3"
k3 = b"f8"
k4 = b"d}"

keys = [k3, k4]
final_keys = []
for key in keys:
    assert len(key) == 2  # 2 byte key into binary
    final_keys.append(bin(key[0])[2:].zfill(8) + bin(key[1])[2:].zfill(8))

cipher = AES.new(final_keys[0].encode(), mode=AES.MODE_ECB)
cipher2 = AES.new(final_keys[1].encode(), mode=AES.MODE_ECB)
enc2 = cipher2.encrypt(cipher.encrypt(enc)).hex()
# should be 0239bcea627d0ff4285a9e114b660ec0e97f65042a8ad209c35a091319541837
print(enc2)

keys = [k1, k2]
final_keys = []
for key in keys:
    assert len(key) == 2  # 2 byte key into binary
    final_keys.append(
        bin(key[0])[2:].zfill(8) + bin(key[1])[2:].zfill(8)
    )
cipher = AES.new(final_keys[0].encode(), mode=AES.MODE_ECB)
cipher2 = AES.new(final_keys[1].encode(), mode=AES.MODE_ECB)
dec = bytes.fromhex(enc2)
dec2 = cipher.decrypt(cipher2.decrypt(dec)).hex()
# should be 4b3d1613610143db984be05ef6f37b31790ad420d28e562ad105c7992882ff34
print(dec2)

# flag = secret_message + k1 + k2 + k3 + k4 (where each key is 2 bytes)
# In this case: scriptCTF{testtesttesttesttest!_AAAABBB}
dec = bytes.fromhex("19574ac010cc9866e733adc616065e6c019d85dd0b46e5c2190c31209fc57727")
dec3 = cipher.decrypt(cipher2.decrypt(dec))
# flag
print(dec3 + k1 + k2 + k3 + k4)
```

Get flag: `scriptCTF{s3cr37_m3ss4g3_1337!_7e4b3f8d}`
