# Reminder

```
Discovering shared patterns through the remainder concept is simple!
```

Decompile the binary in IDA, the binary does:

1. ask 16 questions, save the answers into a vector
2. read from `data.bin`
3. do AES CBC encryption with iv `\xa0\xa1\xa2...\xaf`
4. write to `out.bin`

Initialize strings:

```c
init_string(v110, "\nQuestion 1:\nx ? 4 mod 13\nx ? 4 mod 7\nx ? 0 mod 19\nx = ?\n", 0x39u);
```

Print question, read answer and push_back:

```c
sub_1400052D0(std::cout, v4, v111);
std::istream::operator>>(std::cin, &read_int);
LOBYTE(v60) = read_int;
v5 = (char *)v63[1];
cap = v64;
if ( v63[1] == v64 )
{
sub_140004FE0((const void **)v63, (_BYTE *)v63[1], &v60);
cap = v64;
v7 = v63[1];
}
else
{
*(_BYTE *)v63[1] = read_int;
v7 = v5 + 1;
v63[1] = v7;
}
```

Read data, do AES encryption, write data:

```c
v116[0] = 0;
v117 = 0;
v118 = 15;
init_string(v116, "data.bin", 8u);
v113[0] = 0;
v114 = 0;
v115 = 15;
init_string(v113, "out.bin", 7u);
memset(v120, 0, sizeof(v120));
read_file((__int64)v120, v116);
memset(Block, 0, sizeof(Block));
v37 = (char *)v63[0];
((void (__fastcall *)(void **, void **, void *, _DWORD *, int))aes)(Block, v120, v63[0], v61, v60);
((void (__fastcall *)(void *))write_file)(v113);
getchar();
```

IV:

```c
v61[0] = 0xA3A2A1A0;
v61[1] = 0xA7A6A5A4;
v61[2] = 0xABAAA9A8;
v61[3] = 0xAFAEADAC;
```

How to identify AES? The s-box is well-known:

```c
.rdata:00000001400079C0 ; _BYTE byte_1400079C0[257]
.rdata:00000001400079C0 byte_1400079C0  db 63h, 7Ch, 77h, 7Bh, 0F2h, 6Bh, 6Fh, 0C5h, 30h, 1, 67h
.rdata:00000001400079C0                                         ; DATA XREF: sub_1400016A0+C8↑o
.rdata:00000001400079C0                                         ; aes+5B↑o
.rdata:00000001400079CB                 db 2Bh, 0FEh, 0D7h, 0ABh, 76h, 0CAh, 82h, 0C9h, 7Dh, 0FAh
.rdata:00000001400079D5                 db 59h, 47h, 0F0h, 0ADh, 0D4h, 0A2h, 0AFh, 9Ch, 0A4h, 72h
.rdata:00000001400079DF                 db 0C0h, 0B7h, 0FDh, 93h, 26h, 36h, 3Fh, 0F7h, 0CCh, 34h
.rdata:00000001400079E9                 db 0A5h, 0E5h, 0F1h, 71h, 0D8h, 31h, 15h, 4, 0C7h, 23h
.rdata:00000001400079F3                 db 0C3h, 18h, 96h, 5, 9Ah, 7, 12h, 80h, 0E2h, 0EBh, 27h
.rdata:00000001400079FE                 db 0B2h, 75h, 9, 83h, 2Ch, 1Ah, 1Bh, 6Eh, 5Ah, 0A0h, 52h
.rdata:0000000140007A09                 db 3Bh, 0D6h, 0B3h, 29h, 0E3h, 2Fh, 84h, 53h, 0D1h, 0
.rdata:0000000140007A13                 db 0EDh, 20h, 0FCh, 0B1h, 5Bh, 6Ah, 0CBh, 0BEh, 39h, 4Ah
.rdata:0000000140007A1D                 db 4Ch, 58h, 0CFh, 0D0h, 0EFh, 0AAh, 0FBh, 43h, 4Dh, 33h
```

Solve:

```python
from sympy.ntheory.modular import crt
from Cryptodome.Cipher import AES

lines = open("output", encoding="utf-8").readlines()
key = bytearray()
for i in range(len(lines)):
    if lines[i].startswith("Question"):
        _, _, x1, _, y1 = lines[i + 1].strip().split()
        _, _, x2, _, y2 = lines[i + 2].strip().split()
        _, _, x3, _, y3 = lines[i + 3].strip().split()
        result = crt([int(y1), int(y2), int(y3)], [int(x1), int(x2), int(x3)])
        print(result[0])
        key.append(result[0])

print(key)

cipher = AES.new(
    key,
    AES.MODE_CBC,
    b"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf",
)
print(cipher.decrypt(open("out.bin", "rb").read()))
```

Flag: `ASIS{Remainder_of_Allah_is_better_for_you}`.
