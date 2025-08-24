# Encrypted and Desperate

```
Difficulty: Easy
Author: H4N5

Brunnerne's Royal Court Baker is in a desperate situation. His computer was hit by a ransomware attack that encrypted all his professional brunsviger photos and secret recipes.

The attackers left behind a suspicious ransomware file - it might hold the key to unlock everything, but he doesn't dare touch it without your expert help!
```

Attachment:

```python
import os
from pathlib import Path
from itertools import cycle

TARGET_DIR = Path("./recipes/")

def encrypt(file: Path, key: bytes) -> None:
    with open(file, "rb") as f:
        plaintext = f.read()

    ciphertext = bytes(a ^ b for a, b in zip(plaintext, cycle(key)))

    with open(f"{file}.enc", "wb") as f:
        f.write(ciphertext)

    print(f"Encrypted {file.name}")
    file.unlink() # delete original file, so he can't use it 


if __name__=="__main__":
    key = os.urandom(16)
    print(f"Key: {key.hex(" ")}\n")

    print("Encrypting files...")
    for file in TARGET_DIR.rglob("*"):
        if file.is_file():
            encrypt(file, key)
```

All files are encrypted using the same key. Given the known file extension, we know the starting bytes of PNG/JPG, so we can guess the key:

```python
import os
from pathlib import Path
from itertools import cycle

TARGET_DIR = Path("./recipes/")


def decrypt(file: Path, key: bytes) -> None:
    with open(file, "rb") as f:
        plaintext = f.read()

    ciphertext = bytes(a ^ b for a, b in zip(plaintext, cycle(key)))

    with open(f"{file.name.replace('.enc', '')}", "wb") as f:
        f.write(ciphertext)

    print(f"Decrypted {file.name}")


if __name__ == "__main__":
    key = [
        # PNG header
        0xAF ^ 0x89,
        0xDF ^ 0x50,
        0x38 ^ 0x4E,
        0xEA ^ 0x47,
        0x19 ^ 0x0D,
        0x3B ^ 0x0A,
        0xEB ^ 0x1A,
        0x38 ^ 0x0A,
        # JPG header
        0xCE ^ 0x49,
        0xD9 ^ 0x46,
        0xCB ^ 0x00,
        # Compressed by jpeg
        0x1C ^ ord("p"),
        0x7C ^ ord("r"),
        0x15 ^ ord("e"),
        0x38 ^ ord("s"),
        0xea ^ ord("s"),
    ]
    for file in TARGET_DIR.rglob("*.enc"):
        if file.is_file():
            decrypt(file, key)
```

The first 8 bytes are recovered by known PNG header, the second 3 bytes are from JPG header. After that, we found some `Com?????ed by` text, so it is `Compressed by` in fact, so the last five bytes are found.

The flag is in `WorldClass.pdf`: `brunner{mY_pr3c10u5_r3c1p35_U_f0und_7h3m} `
