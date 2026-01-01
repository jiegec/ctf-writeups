# Day 04

We are given a binary. Decompile:

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 v3; // rdx
  const char *v4; // rdi
  char s[64]; // [rsp+8h] [rbp-50h] BYREF
  unsigned __int64 v7; // [rsp+48h] [rbp-10h]

  v7 = __readfsqword(0x28u);
  sub_1339(a1, a2, a3);
  puts("NPLD Mainframe Authentication");
  __printf_chk(2, "Enter access code: ");
  if ( !fgets(s, 64, stdin) )
    return 1;
  s[strcspn(s, "\n")] = 0;
  if ( strlen(s) != 23 )
  {
    puts("Jingle laughs. Wrong credential length!");
    return 1;
  }
  sub_1339(s, "\n", v3);
  v4 = "Access Denied. Jingle smirks.";
  if ( (unsigned int)sub_1362(s) )
    v4 = "Welcome to the mainframe, Operative. Jingle owes the elves a round.";
  puts(v4);
  return 0;
}
__int64 __fastcall sub_1362(__int64 a1)
{
  __int64 v1; // rax

  v1 = 0;
  while ( (*(char *)(a1 + v1) ^ 0x42) == byte_2110[v1] )
  {
    if ( ++v1 == 23 )
      return 1;
  }
  return 0;
}

.rodata:000000000000210E                 align 10h
.rodata:0000000000002110 ; unsigned __int8 byte_2110[23]
.rodata:0000000000002110 byte_2110       db 21h, 31h, 26h, 39h, 73h, 2Ch, 36h, 72h, 1Dh, 36h, 2Ah
.rodata:0000000000002110                                         ; DATA XREF: sub_1362+6↑o
.rodata:000000000000211B                 db 71h, 1Dh, 2Fh, 76h, 73h, 2Ch, 24h, 30h, 76h, 2Fh, 71h
.rodata:0000000000002126                 db 3Fh
.rodata:0000000000002126 _rodata         ends
.rodata:0000000000002126
```

A simple XOR cipher:

```python
data = bytes.fromhex(
    "21h, 31h, 26h, 39h, 73h, 2Ch, 36h, 72h, 1Dh, 36h, 2Ah, 71h, 1Dh, 2Fh, 76h, 73h, 2Ch, 24h, 30h, 76h, 2Fh, 71h, 3Fh".replace(
        "h, ", ""
    ).removesuffix("h")
)
print(bytes([x ^ 0x42 for x in data]))
```

Solved.
