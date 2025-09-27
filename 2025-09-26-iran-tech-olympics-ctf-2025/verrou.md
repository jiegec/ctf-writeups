# Verrou

```
Try to analyze the Verrou binary to bypass its encryption and recover the secure message from given image!
```

Decompile in IDA:

```c
__int64 __fastcall sub_2A12(__int64 a1, __int64 a2, int width, int height, int const_1, __int64 in_img)
{
  unsigned __int64 v6; // rax
  void *v7; // rsp
  __int64 v8; // rax
  _BYTE v10[8]; // [rsp+8h] [rbp-130h] BYREF
  __int64 v11; // [rsp+10h] [rbp-128h]
  int v12; // [rsp+1Ch] [rbp-11Ch]
  int height_1; // [rsp+20h] [rbp-118h]
  int width_1; // [rsp+24h] [rbp-114h]
  __int64 v15; // [rsp+28h] [rbp-110h]
  __int64 v16; // [rsp+30h] [rbp-108h]
  int v17; // [rsp+38h] [rbp-100h]
  int i; // [rsp+3Ch] [rbp-FCh]
  int j; // [rsp+40h] [rbp-F8h]
  int v20; // [rsp+44h] [rbp-F4h]
  int k; // [rsp+48h] [rbp-F0h]
  int m; // [rsp+4Ch] [rbp-ECh]
  int n; // [rsp+50h] [rbp-E8h]
  int ii; // [rsp+54h] [rbp-E4h]
  int v25; // [rsp+58h] [rbp-E0h]
  int v26; // [rsp+5Ch] [rbp-DCh]
  int v27; // [rsp+60h] [rbp-D8h]
  int v28; // [rsp+64h] [rbp-D4h]
  __int64 v29; // [rsp+68h] [rbp-D0h]
  _BYTE *v30; // [rsp+70h] [rbp-C8h]
  double v31[4]; // [rsp+78h] [rbp-C0h] BYREF
  _BYTE v32[104]; // [rsp+98h] [rbp-A0h] BYREF
  unsigned __int64 v33; // [rsp+100h] [rbp-38h]

  v16 = a1;
  v15 = a2;
  width_1 = width;
  height_1 = height;
  v12 = const_1;
  v11 = in_img;
  v33 = __readfsqword(0x28u);
  sub_361E(v31, 0.0, 0.0, 0.0, 0.0);
  cv::Mat::Mat(v32, (unsigned int)height_1, (unsigned int)width_1, 16, v31);
  v25 = width_1 / v12 * (height_1 / v12);
  v29 = 8 * v25 - 1LL;
  v6 = 16 * ((8 * v25 + 15LL) / 0x10uLL);
  while ( v10 != &v10[-(v6 & 0xFFFFFFFFFFFFF000LL)] )
    ;
  v7 = alloca(v6 & 0xFFF);
  if ( (v6 & 0xFFF) != 0 )
    *(_QWORD *)&v10[(v6 & 0xFFF) - 8] = *(_QWORD *)&v10[(v6 & 0xFFF) - 8];
  v30 = v10;
  v17 = 0;
  for ( i = 0; i < v25; ++i )
  {
    for ( j = 0; j <= 7; ++j )
      v30[v17++] = (*(char *)(i + v11) >> j) & 1;
  }
  v20 = 0;
  for ( k = 0; k < height_1 / v12; ++k )
  {
    for ( m = 0; m < width_1 / v12; ++m )
    {
      for ( n = 0; n < v12; ++n )
      {
        for ( ii = 0; ii < v12; ++ii )
        {
          v26 = v12 * k + n;
          v27 = v12 * m + ii;
          v28 = 255 * (char)v30[v20];
          pixel((__int64)v31, v28, v28, v28);
          v8 = addr((__int64)v32, v26, v27);
          *(_WORD *)v8 = LOWORD(v31[0]);
          *(_BYTE *)(v8 + 2) = BYTE2(v31[0]);
        }
      }
      ++v20;
    }
  }
  cv::Mat::Mat(v16, v32);
  cv::Mat::~Mat((cv::Mat *)v32);
  return v16;
}
```

It breaks the input data into bits, and each bit is mapped to a pixel. So we just read the pixels out and reconstruct the input.

Solve:

```python
import numpy as np
from PIL import Image

img = Image.open("flag.jpg")
data = np.array(img)
bits = ""
for i in range(40):
    for j in range(313):
        if data[i][j][0] < 128:
            bits += "0"
        else:
            bits += "1"

assert len(bits) == 40 * 313
res = bytearray()
for i in range(5):
    for j in range(313):
        index = (i * 313 + j) * 8
        # from LSB to MSB
        part = bits[index:index+8][::-1]
        value = int(part, 2)
        res.append(value)
print(res[:res.index(b"\x00")].decode())
```

Output is an ASCII art:

```
    _    ____ ___ ____    ___  _          ___ _____ _     _____ ____      _____ _ _ _____   _____ ___     _           _  _         _____     _____             ___      _ ___       ___  ___   
   / \  / ___|_ _/ ___|  / / || |  _ __  / _ \_   _| |__ |___ /|  _ \    |  ___| | |___ /  |___  / _ \   / |_ __ ___ | || |   __ _| ____|   | ____|_ __   ___ / _ \  __| |_ _|_ __ / _ \| \ \  
  / _ \ \___ \| |\___ \ | || || |_| '_ \| | | || | | '_ \  |_ \| |_) |   | |_  | | | |_ \     / / | | |  | | '_ ` _ \| || |_ / _` |  _|     |  _| | '_ \ / __| | | |/ _` || || '_ \ (_) | || | 
 / ___ \ ___) | | ___) < < |__   _| | | | |_| || | | | | |___) |  _ <    |  _| |_| |___) |   / /| |_| |  | | | | | | |__   _| (_| | |___    | |___| | | | (__| |_| | (_| || || | | \__, |_| > >
/_/   \_\____/___|____/ | |   |_| |_| |_|\___/ |_| |_| |_|____/|_| \_\___|_|   (_)_|____/___/_/  \___/___|_|_| |_| |_|  |_|  \__, |_____|___|_____|_| |_|\___|\___/ \__,_|___|_| |_| /_/(_)| | 
                         \_\                                        |_____|            |_____|      |_____|                  |___/     |_____|                                            /_/  
```

Flag: `ASIS{4n0Th3R_F!l3_7O_1m4gE_Enc0dIn9!}`. Actually, the `0` and `O` are indisguishable, so I had to open a ticket for clarification.
