# hidden_strings

```
This binary seems to be giving me some prompts but where are these strings coming from??

note: for the flag use the part of it that looks like it might sense. There is a slight bug in the challenge :)
```

Decompile the attachment in Ghidra:

```c

undefined8 main(void)

{
  long lVar1;
  undefined **ppuVar2;
  char *pcVar3;
  size_t sVar4;
  byte *input_buffer;
  ulong uVar5;
  ulong uVar6;
  byte *pbVar7;
  uint uVar8;
  byte bVar9;
  byte bVar10;
  ulong uVar11;
  byte *pbVar12;
  undefined8 uVar13;
  long in_FS_OFFSET;
  uint64_t local_188 [2];
  uint64_t local_178 [4];
  uint64_t local_158 [6];
  int local_128;
  byte local_124 [13];
  byte local_117 [247];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  input_buffer = (byte *)&local_128;
  local_178[0] = 0;
  local_178[1] = 1;
  local_178[2] = 2;
  local_178[3] = 3;
  decode_and_print(local_178,4,1);
  local_188[0] = 4;
  local_188[1] = 5;
  decode_and_print(local_188,2,0);
  fputc(0x20,stdout);
  pcVar3 = fgets((char *)input_buffer,0x100,stdin);
  if (pcVar3 == (char *)0x0) {
    uVar13 = 1;
  }
  else {
    uVar13 = 0;
    sVar4 = strcspn((char *)input_buffer,"\r\n");
    local_124[sVar4 - 4] = 0;
    if (local_128 == 0x7b4f4e45) {
      sVar4 = strlen((char *)input_buffer);
      if (local_124[(long)((int)sVar4 + -1) + -4] == 0x7d) {
        if (sVar4 != 0) {
          pbVar12 = input_buffer + sVar4;
          do {
            bVar9 = *input_buffer;
            uVar8 = (int)input_buffer + 0x61U & 3;
            bVar10 = bVar9 ^ 0x61;
            if ((uVar8 != 1) && (uVar8 == 3)) {
              bVar10 = (bVar9 | 0x61) & ~(bVar9 & 0x61);
            }
            *input_buffer = bVar10;
            input_buffer = input_buffer + 1;
          } while (input_buffer != pbVar12);
          if (5 < sVar4) {
            input_buffer = local_124;
            pbVar12 = &DAT_00102021;
            do {
              uVar11 = (ulong)pbVar12[-1];
              bVar9 = 0;
              if (uVar11 < 0x30) {
                uVar6 = (ulong)*pbVar12;
                lVar1 = uVar11 * 0x18;
                ppuVar2 = &PTR_DAT_00104160 + uVar11 * 3;
                if (uVar6 < *(long *)(&DAT_00104168 + lVar1) - 1U) {
                  if (*(long *)(&DAT_00104168 + lVar1) == 0) {
                    bVar9 = (*ppuVar2)[uVar6] ^ 0x61;
                  }
                  else {
                    uVar5 = 0;
                    do {
                      pbVar7 = *ppuVar2 + uVar5;
                      uVar5 = uVar5 + 1;
                      *pbVar7 = *pbVar7 ^ (&DAT_00104170)[lVar1];
                    } while (uVar5 < *(ulong *)(&DAT_00104168 + lVar1));
                    bVar9 = (*ppuVar2)[uVar6] ^ 0x61;
                    if (*(ulong *)(&DAT_00104168 + lVar1) != 0) {
                      uVar6 = 0;
                      do {
                        pbVar7 = (&PTR_DAT_00104160)[uVar11 * 3] + uVar6;
                        uVar6 = uVar6 + 1;
                        *pbVar7 = *pbVar7 ^ (&DAT_00104170)[uVar11 * 0x18];
                      } while (uVar6 < *(ulong *)(&DAT_00104168 + uVar11 * 0x18));
                    }
                  }
                }
              }
              if (*input_buffer != bVar9) goto LAB_00101388;
              input_buffer = input_buffer + 1;
              pbVar12 = pbVar12 + 2;
            } while (local_117 != input_buffer);
            local_158[0] = 7;
            local_158[1] = 5;
            decode_and_print(local_158,2,1);
            goto LAB_0010120e;
          }
        }
LAB_00101388:
        local_158[0] = 6;
        local_158[1] = 5;
        uVar13 = 2;
        local_158[2] = 0x26;
        local_158[3] = 0x27;
        local_158[4] = 0x28;
        decode_and_print(local_158,5,1);
      }
    }
  }
LAB_0010120e:
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar13;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

There is a `decode_and_print` function that xors data from `.data` section and print it out:

```c
void decode_and_print(uint64_t *array,long length,int eol)

{
  ulong *puVar1;
  
  puVar1 = array + length;
  while( true ) {
    if (*array < 0x30) {
      FUN_00101550(*array);
    }
    array = array + 1;
    if (array == puVar1) break;
    fputc(0x20,stdout);
  }
  if (eol == 0) {
    return;
  }
  fputc(10,stdout);
  return;
}


void FUN_00101550(uint64_t param_1)

{
  long lVar1;
  ulong uVar2;
  byte *pbVar3;
  size_t __n;
  
  lVar1 = param_1 * 0x18;
  if (*(long *)(&DAT_00104168 + lVar1) == 0) {
    __n = 0xffffffffffffffff;
  }
  else {
    uVar2 = 0;
    do {
      pbVar3 = (&PTR_DAT_00104160)[param_1 * 3] + uVar2;
      uVar2 = uVar2 + 1;
      *pbVar3 = *pbVar3 ^ (&DAT_00104170)[lVar1];
    } while (uVar2 < *(ulong *)(&DAT_00104168 + lVar1));
    __n = *(ulong *)(&DAT_00104168 + lVar1) - 1;
  }
  lVar1 = param_1 * 0x18;
  fwrite((&PTR_DAT_00104160)[param_1 * 3],1,__n,stdout);
  uVar2 = 0;
  if (*(long *)(&DAT_00104168 + lVar1) != 0) {
    do {
      pbVar3 = (&PTR_DAT_00104160)[param_1 * 3] + uVar2;
      uVar2 = uVar2 + 1;
      *pbVar3 = *pbVar3 ^ (&DAT_00104170)[lVar1];
    } while (uVar2 < *(ulong *)(&DAT_00104168 + lVar1));
  }
  return;
}
```

So we write a python script to dump all these xor-ed strings from `.data` section:

```python
from pwn import *

e = ELF("./challenge")

base = 0x4160
s = dict()
for i in range(0x30):
    addr = u64(e.read(base + i * 24, 8))
    length = u64(e.read(base + i * 24 + 8, 8))
    xor = u64(e.read(base + i * 24 + 16, 8))
    print(hex(i) + ": ", end="")
    temp = ""
    for j in range(length - 1):
        ch = chr(e.read(addr + j, 1)[0] ^ xor)
        print(ch, end="")
        temp += ch
    s[i] = temp
    print()
```

Output:

```
0x0: welcome
0x1: to
0x2: ENO
0x3: challenge
0x4: enter
0x5: flag
0x6: wrong
0x7: correct
0x8: debug
0x9: reached
0xa: step
0xb: length
0xc: ok
0xd: checking
0xe: piece
0xf: stack
0x10: strings
0x11: are
0x12: fun
0x13: xor
0x14: obfuscation
0x15: is
0x16: sneaky
0x17: players
0x18: love
0x19: puzzles
0x1a: only
0x1b: decode
0x1c: when
0x1d: needed
0x1e: now
0x1f: you
0x20: see
0x21: me
0x22: dont
0x23: random
0x24: filler
0x25: text
0x26: please
0x27: try
0x28: again
0x29: with
0x2a: check
0x2b: user
0x2c: input
0x2d: pre
0x2e: post
0x2f: bytes
```

The strings that we see from the output of the binary comes from these strings, e.g.:

```c
// prints the 0, 1, 2, 3-rd strings from the table: welcome to ENO challenge
local_178[0] = 0;
local_178[1] = 1;
local_178[2] = 2;
local_178[3] = 3;
decode_and_print(local_178,4,1)
// prints the 4, 5-th strings from the table: enter flag
local_188[0] = 4;
local_188[1] = 5;
decode_and_print(local_188,2,0);
// prints the 7, 5-th strings from the table: correct flag
local_158[0] = 7;
local_158[1] = 5;
decode_and_print(local_158,2,1);
// prints the 6, 5, 0x26, 0x27, 0x28-th strings from the table: wrong flag please try again
local_158[0] = 6;
local_158[1] = 5;
uVar13 = 2;
local_158[2] = 0x26;
local_158[3] = 0x27;
local_158[4] = 0x28;
decode_and_print(local_158,5,1);
```

Now, we need to find the correct flag. Validations include:

```c
if (local_128 == 0x7b4f4e45) {
    if (local_124[(long)((int)sVar4 + -1) + -4] == 0x7d) {
        // ...
    }
}
```

The flag should start with `ENO{` and end with `}`.

Afterwards, the program reads one byte from one string, which is later checked against the flag input:

```c
uVar11 = (ulong)pbVar12[-1];
bVar9 = 0;
if (uVar11 < 0x30) {
  uVar6 = (ulong)*pbVar12;
  lVar1 = uVar11 * 0x18;
  ppuVar2 = &PTR_DAT_00104160 + uVar11 * 3;
  if (uVar6 < *(long *)(&DAT_00104168 + lVar1) - 1U) {
    if (*(long *)(&DAT_00104168 + lVar1) == 0) {
      bVar9 = (*ppuVar2)[uVar6] ^ 0x61;
    }
    else {
      uVar5 = 0;
      do {
        pbVar7 = *ppuVar2 + uVar5;
        uVar5 = uVar5 + 1;
        *pbVar7 = *pbVar7 ^ (&DAT_00104170)[lVar1];
      } while (uVar5 < *(ulong *)(&DAT_00104168 + lVar1));
      bVar9 = (*ppuVar2)[uVar6] ^ 0x61;
      if (*(ulong *)(&DAT_00104168 + lVar1) != 0) {
        uVar6 = 0;
        do {
          pbVar7 = (&PTR_DAT_00104160)[uVar11 * 3] + uVar6;
          uVar6 = uVar6 + 1;
          *pbVar7 = *pbVar7 ^ (&DAT_00104170)[uVar11 * 0x18];
        } while (uVar6 < *(ulong *)(&DAT_00104168 + uVar11 * 0x18));
      }
    }
  }
}
```

The string number and the character index is saved in an array starting from 0x102020:

```
                             DAT_00102020                                    XREF[1]:     main:001012c0(R)  
        00102020 0a              undefined1 0Ah
                             DAT_00102021                                    XREF[2]:     main:001012ac(*), 
                                                                                          main:001012d1(R)  
        00102021 00              undefined1 00h
                             DAT_00102022                                    XREF[1]:     main:001012c0(R)  
        00102022 01              undefined1 01h
                             DAT_00102023                                    XREF[1]:     main:001012d1(R)  
        00102023 00              undefined1 00h
        00102024 03              ??         03h
        00102025 02              ??         02h
        00102026 00              ??         00h
        00102027 03              ??         03h
        00102028 0c              ??         0Ch
        00102029 01              ??         01h
        0010202a 13              ??         13h
        0010202b 00              ??         00h
        0010202c 00              ??         00h
        0010202d 04              ??         04h
        0010202e 04              ??         04h
        0010202f 04              ??         04h
        00102030 06              ??         06h
        00102031 01              ??         01h
        00102032 01              ??         01h
        00102033 01              ??         01h
        00102034 03              ??         03h
        00102035 00              ??         00h
        00102036 0d              ??         0Dh
        00102037 04              ??         04h
        00102038 0f              ??         0Fh
        00102039 00              ??         00h
```

So we just print them out:

```python
from pwn import *

e = ELF("./challenge")

base = 0x4160
s = dict()
for i in range(0x30):
    addr = u64(e.read(base + i * 24, 8))
    length = u64(e.read(base + i * 24 + 8, 8))
    xor = u64(e.read(base + i * 24 + 16, 8))
    print(hex(i) + ": ", end="")
    temp = ""
    for j in range(length - 1):
        ch = chr(e.read(addr + j, 1)[0] ^ xor)
        print(ch, end="")
        temp += ch
    s[i] = temp
    print()


data = [
    0x0A,
    0x00,
    0x01,
    0x00,
    0x03,
    0x02,
    0x00,
    0x03,
    0x0C,
    0x01,
    0x13,
    0x00,
    0x00,
    0x04,
    0x04,
    0x04,
    0x06,
    0x01,
    0x01,
    0x01,
    0x03,
    0x00,
    0x0D,
    0x04,
    0x0F,
    0x00
]

for i in range(0, len(data), 2):
    if data[i+1] < len(s[data[i]]):
        print(s[data[i]][data[i+1]], end="")
```

Output:

```
stackxorrocks
```

So the flag is `ENO{stackxorrocks}`:

```shell
$ ./challenge
welcome to ENO challenge
enter flag ENO{stackxorrocks}
correct flag
```
