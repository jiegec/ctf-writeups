# Mod

Provided code

```python
#!/usr/local/bin/python3
import os
secret = int(os.urandom(32).hex(),16)
print("Welcome to Mod!")
num=int(input("Provide a number: "))
print(num % secret)
guess = int(input("Guess: "))
if guess==secret:
    print(open('flag.txt').read())
else:
    print("Incorrect!")
```

Set num to `2**256`, hope that `num % secret` equals to `num - secret`.

Code:

```python
from pwn import *

context(log_level="debug")

p = remote("play.scriptsorcerers.xyz", 10372)
#p = process("./mod-chall.py")
p.sendline(f"{2**256}")
l = int(p.recvuntil("Guess").splitlines()[1].split()[-1])
print(l)
p.sendline(f"{2**256-l}")
p.interactive()
```

Get flag: `scriptCTF{-1_f0r_7h3_w1n_4a3f7db1_b94964163bb2}`.
