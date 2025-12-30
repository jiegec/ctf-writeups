# Fautif

```
Reverse the Fautif binary to uncover the hidden flag and prove its malicious intent.
```

Decompile the attachment in ghidra:

```c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 main(int argc,char **argv)

{
  undefined *puVar1;
  int iVar2;
  int iVar3;
  __ssize_t _Var4;
  size_t lineptr_len;
  byte *out_buf;
  time_t tVar5;
  size_t sVar6;
  undefined *puVar7;
  byte *pbVar8;
  byte local_8 [8];
  byte *pbVar9;
  
  puVar7 = PTR_DAT_001202b0;
  DAT_001202e0 = PTR_DAT_001202b0 + 0x28;
  DAT_001202d0 = PTR_DAT_001202b0 + 0x2c;
  *(undefined8 *)(PTR_DAT_001202b0 + 0x1c) = 0x100000000;
  *(undefined4 *)(puVar7 + 0x24) = 2;
  DAT_001202e8 = puVar7 + 0x30;
  DAT_001202d8 = &DAT_0012015d;
  DAT_001202f0 = s_RFWKA_00120153;
  FUN_00100e08();
  puVar7 = &DAT_00120183;
  do {
    puVar1 = puVar7 + 0x1b;
    FUN_00100f40(puVar7);
    puVar7 = puVar1;
  } while (puVar1 != &DAT_0012020a);
  FUN_00100e08();
  _Var4 = getdelim((char **)&lineptr,(size_t *)&size,-1,_stdin);
  if (0 < _Var4) {
    FUN_00100f40(lineptr);
  }
  lineptr_len = strlen((char *)lineptr);
  out_buf = (byte *)malloc(lineptr_len + 1);
  tVar5 = time((time_t *)0x0);
  srand((uint)tVar5);
  iVar2 = rand();
  local_8[0] = (byte)iVar2;
  iVar3 = rand();
  pbVar9 = lineptr;
  local_8[1] = (char)iVar3;
  if (lineptr_len != 0) {
    *out_buf = (byte)iVar2 ^ *lineptr;
    if (lineptr_len != 1) {
      sVar6 = 1;
      do {
        out_buf[sVar6] = local_8[sVar6 & 1] ^ pbVar9[sVar6];
        sVar6 = sVar6 + 1;
      } while (lineptr_len != sVar6);
    }
    out_buf[lineptr_len] = 0;
    pbVar9 = out_buf;
    do {
      pbVar8 = pbVar9 + 1;
      printf("%02x",(ulong)*pbVar9);
      pbVar9 = pbVar8;
    } while (pbVar8 != out_buf + lineptr_len);
  }
  free(out_buf);
  free(lineptr);
  return 0;
}
```

The code does:

1. prepare some data
2. read line from stdin
3. transform stdin data
4. xor with two random numbers and print

So we need to recover the transformation and the two random numbers. To recover the transformation, we use `ltrace` to trace `strlen` calls to the transformed text:

```shell
$ echo -n "a" | ltrace -e strlen ./Fautif
Fautif->strlen("g")                                                                        = 1
f0+++ exited (status 0) +++
$ echo -n "aa" | ltrace -e strlen ./Fautif
Fautif->strlen("gb")                                                                       = 2
c435+++ exited (status 0) +++
$ echo -n "aaa" | ltrace -e strlen ./Fautif
Fautif->strlen("gba")                                                                      = 3
88698e+++ exited (status 0) +++
$ echo -n "a{aa" | ltrace -e strlen ./Fautif
Fautif->strlen("g{ba")                                                                     = 4
4a244f3e+++ exited (status 0) +++
```

Observations:

1. the mapping is fixed, from the character with its index, to the output
2. the index ignores non-letters, e.g. `{`

So we can just enumerate all mappings, bruteforce the xor-ed random numbers to find flag:

```python
import string
import os

# find all mappings from (character, position) to character
mapping = dict()
for ch in string.ascii_letters + "_{}!":
    os.system(f"echo -n \"{ch * 128}\" | ltrace -o strace.log -e strlen -s 1000 ./Fautif >/dev/null")
    res = open("strace.log", "r").read()
    out = res.split("(\"")[1].split("\")")[0]
    print(ch, out)
    for i, c in enumerate(out):
        mapping[(c, i)] = ch


# reverse last step of xor with two random numbers
data = bytes.fromhex(open("flag.enc", "r").read())
for r1 in range(256):
    for r2 in range(256):
        recovered = bytearray()
        for i in range(len(data)):
            if i % 2 == 0:
                recovered.append(data[i] ^ r1)
            else:
                recovered.append(data[i] ^ r2)
        if all(chr(ch) in (string.digits + string.ascii_letters + string.punctuation + "\n") for ch in recovered):
            s = ""
            for i, c in enumerate(recovered):
                # skip non letters
                i -= recovered[:i].count(b"{") + recovered[:i].count(b"_")
                key = (chr(c), i)
                if key in mapping:
                    s += mapping[key]
            if "ASIS" in s:
                print(recovered, s)
```

Flag: `ASIS{The_Enigma_cipher_was_a_system_created_using_electromechanical_machines_to_encrypt_and_decrypt_messages!}`.

Only after getting the flag, I realize that it is an implementation of Enigma. 2nd solve:

```
First 3 solves
WTN
solved in 0d 12h 7m 24s
jiegec
solved in 0d 13h 11m 57s
```
