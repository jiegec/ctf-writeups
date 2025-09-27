# Tangle

```
Tangle offers a beginner-friendly reverse engineering challenge, perfect for diving deep into binary analysis during the Olympic CTF.
```

Decompile the code in IDA:

```c
__int64 __fastcall sub_235A(__int64 a1, __int64 a2)
{
  int v2; // eax
  char v3; // al
  _BYTE v6[45]; // [rsp+10h] [rbp-50h] BYREF
  char v7; // [rsp+3Dh] [rbp-23h]
  char v8; // [rsp+3Eh] [rbp-22h]
  char v9; // [rsp+3Fh] [rbp-21h]
  unsigned int v10; // [rsp+40h] [rbp-20h]
  int j; // [rsp+44h] [rbp-1Ch]
  int v12; // [rsp+48h] [rbp-18h]
  int i; // [rsp+4Ch] [rbp-14h]

  v2 = rand();
  v10 = (unsigned __int8)(((unsigned int)(v2 >> 31) >> 24) + v2) - ((unsigned int)(v2 >> 31) >> 24);
  std::string::basic_string(a1);
  for ( i = 0; i < (unsigned __int64)std::string::size(a2); ++i )
  {
    v9 = *(_BYTE *)std::string::operator[](a2, i);
    v8 = rand();
    v7 = v8 ^ v9 ^ ((int)(i + v10) % 256);
    if ( (i & 3) != 0 )
    {
      if ( i % 4 == 1 )
      {
        std::string::operator+=(a1, (unsigned int)(char)((v7 + 216) % 256));
        std::string::operator+=(a1, (unsigned int)v8);
      }
      else if ( i % 4 == 2 )
      {
        std::string::operator+=(a1, (unsigned int)v7);
        std::string::operator+=(a1, (unsigned int)v8);
        std::string::operator+=(a1, (unsigned int)(char)dword_6300[i % 41 * i % 41 * (i % 41) % 41]);
      }
      else
      {
        std::string::operator+=(a1, (unsigned int)v8);
        std::string::operator+=(a1, (unsigned int)v7);
        v3 = rand();
        std::string::operator+=(a1, (unsigned int)v3);
      }
    }
    else
    {
      std::string::operator+=(a1, (unsigned int)(char)((v8 + 114) % 256));
      std::string::operator+=(a1, (unsigned int)v7);
    }
  }
  v12 = std::string::size(a1) / 0x28uLL + 1;
  std::string::basic_string(v6);
  while ( v12-- )
  {
    for ( j = 0; j <= 39; ++j )
      std::string::operator+=(v6, (unsigned int)(char)dword_6300[j]);
  }
  std::string::~string(v6);
  return a1;
}
```

It converts input to output using the code above. Although there are random numbers, we only need `v7` and `v8`. By enumerating `v10`, we can recover the input string. Once we find the correct input string, a PNG file is decoded:

```python
data = open("flag.enc", "rb").read()

# find input length
i = 0
length = 0
while length < len(data):
    if i % 4 == 1:
        length += 2
    elif i % 4 == 2:
        length += 3
    elif i % 4 == 3:
        length += 3
    else:
        length += 2
    i += 1

assert length == len(data)
print(i)

# reverse, enumerate v10
for v10 in range(256):
    length = 0
    flag = bytearray()
    for j in range(i):
        if j % 4 == 1:
            v7 = (data[length] - 216 + 256) % 256
            v8 = data[length + 1]
            length += 2
        elif j % 4 == 2:
            v7 = data[length]
            v8 = data[length + 1]
            length += 3
        elif j % 4 == 3:
            v7 = data[length + 1]
            v8 = data[length]
            length += 3
        else:
            v7 = data[length + 1]
            v8 = (data[length] - 114 + 256) % 256
            length += 2
        v9 = v7 ^ v8 ^ ((j + v10) % 256)
        flag.append(v9)
    assert length == len(data)
    if b"PNG" in flag:
        open("dump.png", "wb").write(flag)
        print("Written to dump.png")
        break
```

![](./tangle.png)

Flag: `ASIS{a_CTF_pl4y3r_Alway5_r3adS_aSseM8ly_c0dEs!}`.
