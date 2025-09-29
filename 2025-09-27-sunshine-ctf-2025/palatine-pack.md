# Palatine Pack

```
Caesar is raiding the Roman treasury to pay off his debts to his Gallic allies, and to you and his army. Help him find the password to make this Lucius Caecilius Metellus guy give up the money! >:) (he is sacrosanct so no violence!)

    currently has nonstandard flag format sunshine{}
```

Decompile in IDA:

```c
__int64 __fastcall flipBits(__int64 a1, int a2)
{
  __int64 result; // rax
  char v3; // [rsp+13h] [rbp-9h]
  _BOOL4 v4; // [rsp+14h] [rbp-8h]
  unsigned int i; // [rsp+18h] [rbp-4h]

  v4 = 0;
  v3 = 105;
  for ( i = 0; ; ++i )
  {
    result = i;
    if ( (int)i >= a2 )
      break;
    if ( v4 )
    {
      *(_BYTE *)((int)i + a1) ^= v3;
      v3 += 32;
    }
    else
    {
      *(_BYTE *)((int)i + a1) = ~*(_BYTE *)((int)i + a1);
    }
    v4 = !v4;
  }
  return result;
}

_BYTE *__fastcall expand(__int64 a1, int a2)
{
  unsigned __int8 v3; // [rsp+1Bh] [rbp-15h]
  _BOOL4 v4; // [rsp+1Ch] [rbp-14h]
  int i; // [rsp+20h] [rbp-10h]
  _BYTE *v6; // [rsp+28h] [rbp-8h]

  v4 = 0;
  v3 = 105;
  v6 = malloc(2 * a2);
  for ( i = 0; i < a2; ++i )
  {
    if ( v4 )
    {
      v6[2 * i] = (v3 >> 4) | *(_BYTE *)(i + a1) & 0xF0;
      v6[2 * i + 1] = (16 * v3) | *(_BYTE *)(i + a1) & 0xF;
    }
    else
    {
      v6[2 * i] = (16 * v3) | *(_BYTE *)(i + a1) & 0xF;
      v6[2 * i + 1] = (v3 >> 4) | *(_BYTE *)(i + a1) & 0xF0;
    }
    v3 *= 11;
    v4 = !v4;
  }
  printf("fie");
  return v6;
}

int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned __int64 v3; // rax
  void *v4; // rsp
  char v6[8]; // [rsp+8h] [rbp-80h] BYREF
  int i; // [rsp+10h] [rbp-78h]
  int n; // [rsp+14h] [rbp-74h]
  FILE *stream; // [rsp+18h] [rbp-70h]
  __int64 v10; // [rsp+20h] [rbp-68h]
  char *s; // [rsp+28h] [rbp-60h]
  __int64 v12; // [rsp+30h] [rbp-58h]
  __int64 v13; // [rsp+38h] [rbp-50h]
  void *ptr; // [rsp+40h] [rbp-48h]
  FILE *v15; // [rsp+48h] [rbp-40h]
  unsigned __int64 v16; // [rsp+50h] [rbp-38h]

  v16 = __readfsqword(0x28u);
  puts("\nMay Jupiter strike you down Caeser before you seize the treasury!! You will have to tear me apart");
  puts("for me to tell you the flag to unlock the Roman Treasury and fund your civil war. I, Lucius Caecilius");
  puts("Metellus, shall not let you pass until you get this password right. (or threaten to kill me-)\n");
  stream = fopen("palatinepackflag.txt", "r");
  fseek(stream, 0, 2);
  n = ftell(stream) + 1;
  fseek(stream, 0, 0);
  v10 = n - 1LL;
  v3 = 16 * ((n + 15LL) / 0x10uLL);
  while ( v6 != &v6[-(v3 & 0xFFFFFFFFFFFFF000LL)] )
    ;
  v4 = alloca(v3 & 0xFFF);
  if ( (v3 & 0xFFF) != 0 )
    *(_QWORD *)&v6[(v3 & 0xFFF) - 8] = *(_QWORD *)&v6[(v3 & 0xFFF) - 8];
  s = v6;
  fgets(v6, n, stream);
  flipBits(s, (unsigned int)n);
  v12 = expand(s, (unsigned int)n);
  v13 = expand(v12, (unsigned int)(2 * n));
  ptr = (void *)expand(v13, (unsigned int)(4 * n));
  anti_debug();
  for ( i = 0; i < 8 * n; ++i )
    putchar(*((unsigned __int8 *)ptr + i));
  putchar(10);
  v15 = fopen("flag.txt", "wb");
  fwrite(ptr, 1u, 8 * n, v15);
  fclose(v15);
  return 0;
}
```

Four reversible steps are done to the input (flipBits + 3x expand). Reverse the steps to get flag:

```python
data = open("flag.txt", "rb").read()


def collapse(s):
    res = bytearray()
    for i in range(len(s) // 2):
        if i % 2 == 0:
            # lo, hi
            res.append(((s[2 * i]) & 0x0F) | ((s[2 * i + 1]) & 0xF0))
        else:
            # hi, lo
            res.append(((s[2 * i]) & 0xF0) | ((s[2 * i + 1]) & 0x0F))
    return res


data = collapse(data)
data = collapse(data)
data = collapse(data)

# flip bits
v3 = 105
for i in range(len(data)):
    if i % 2 == 0:
        data[i] = ~data[i] & 0xFF
    else:
        data[i] ^= v3 & 0xFF
        v3 += 32
print(data)
```

Flag: `sunshine{C3A5ER_CR055ED_TH3_RUB1C0N}`.