# Based Brunner

```
Difficulty: Beginner
Author: Nissen

Brunsviger is just so based, I think I could eat it in any form - from binary to decimal!

Tip: This might require a bit of programming, I would recommend looking into the int() function in Python.
```

Attachment:

```python
def encode_char(ch: str, base: int) -> str:
    """
    Encode a single character into a string of digits in the given base
    """
    value = ord(ch)
    digits = []
    while value > 0:
        digits.append(str(value % base))
        value //= base

    return "".join(reversed(digits))


with open("flag.txt") as f:
    text = f.read().strip()

# Encode the text with all bases from decimal to binary
for base in range(10, 1, -1):
    text = " ".join(encode_char(ch, base) for ch in text)

with open("based.txt", "w") as f:
    f.write(text)
```

Create a python script that reverses the process:

```python
def decode(digits: str, base: int) -> str:
    num = int(digits, base)

    return chr(num)

with open("based.txt") as f:
    text = f.read().strip()

for base in range(2, 11, 1):
    parts = text.split()
    text = "".join([decode(part, base) for part in parts])

with open("flag.txt", "w") as f:
    f.write(text)
```

Get flag: `brunner{1s_b4s3d}`
