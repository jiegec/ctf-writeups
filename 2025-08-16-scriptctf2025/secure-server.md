# Secure-Server

```
John Doe uses this secure server where plaintext is never shared. Our Forensics Analyst was able to capture this traffic and the source code for the server. Can you recover John Doe's secrets?
```

Unzip the provided file, found a pcap file. Use wireshark to extract the content of TCP stream:

```
With the Secure Server, sharing secrets is safer than ever!
Enter the secret, XORed by your key (in hex): 
151e71ce4addf692d5bac83bb87911a20c39b71da3fa5e7ff05a2b2b0a83ba03

Double encrypted secret (in hex): e1930164280e44386b389f7e3bc02b707188ea70d9617e3ced989f15d8a10d70
XOR the above with your key again (in hex): 
87ee02c312a7f1fef8f92f75f1e60ba122df321925e8132068b0871ff303960e

Secret received!
```

The provided python file:

```python
import os
from pwn import xor
print("With the Secure Server, sharing secrets is safer than ever!")
enc = bytes.fromhex(input("Enter the secret, XORed by your key (in hex): ").strip())
key = os.urandom(32)
enc2 = xor(enc,key).hex()
print(f"Double encrypted secret (in hex): {enc2}")
dec = bytes.fromhex(input("XOR the above with your key again (in hex): ").strip())
secret = xor(dec,key)
print("Secret received!")
```

Simply repeat the process using known values from the pcap.

```python
from pwn import xor
enc = bytes.fromhex("151e71ce4addf692d5bac83bb87911a20c39b71da3fa5e7ff05a2b2b0a83ba03")
enc2 = bytes.fromhex("e1930164280e44386b389f7e3bc02b707188ea70d9617e3ced989f15d8a10d70")
key = xor(enc, enc2)
print(key.hex())
dec = bytes.fromhex("87ee02c312a7f1fef8f92f75f1e60ba122df321925e8132068b0871ff303960e")
secret = xor(dec, key)
print(secret.hex())
print(bytearray.fromhex(secret.hex()).decode())
```

Get flag: `scriptCTF{x0r_1s_not_s3cur3!!!!}`
