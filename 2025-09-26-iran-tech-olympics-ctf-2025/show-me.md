# Show me

```
The output of a binary program, Show me, is available to researchers to analyze its functionality and find a hidden message. Seeing is believing.
```

Decompile the attachment in IDA:

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  unsigned int v3; // eax
  int i; // [rsp+4h] [rbp-4ACh]
  int j; // [rsp+8h] [rbp-4A8h]
  int v7; // [rsp+14h] [rbp-49Ch]
  char *ptr; // [rsp+18h] [rbp-498h]
  _BYTE v9[849]; // [rsp+20h] [rbp-490h] BYREF
  char v10[15]; // [rsp+371h] [rbp-13Fh] BYREF
  char v11[32]; // [rsp+380h] [rbp-130h] BYREF
  char s[264]; // [rsp+3A0h] [rbp-110h] BYREF
  unsigned __int64 v13; // [rsp+4A8h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  strcpy(v11, "0123456789abcdef");
  v3 = time(0);
  srand(v3);
  for ( i = 0; i <= 13; ++i )
    v10[i] = v11[rand() % 16];
  v10[14] = 0;
  ptr = (char *)malloc(0xE9u);
  if ( ptr )
  {
    printf("Enter secret text: ");
    if ( fgets(s, 256, stdin) )
    {
      s[strcspn(s, "\n")] = 0;
      if ( s[0] )
      {
        v7 = strlen(s);
        if ( v7 <= 37 )
        {
          for ( j = v7; j <= 37; ++j )
          {
            if ( j % 3 )
            {
              if ( j % 3 == 1 )
                s[j] = '+';
              else
                s[j] = '-';
            }
            else
            {
              s[j] = '*';
            }
          }
          s[38] = 0;
        }
        convert_to_qrcode((__int64)s, v9);
        encode(v9, ptr);
        printf("Ciphertext: \n%s%s\n", v10, ptr);
        free(ptr);
        return 0;
      }
      else
      {
        puts("No input provided.");
        free(ptr);
        return 1;
      }
    }
    else
    {
      puts("Input error.");
      free(ptr);
      return 1;
    }
  }
  else
  {
    fwrite("Error: Memory allocation failed.\n", 1u, 0x21u, stderr);
    return 1;
  }
}

char *__fastcall encode(char *a1, char *a2)
{
  unsigned __int8 v3; // [rsp+1Bh] [rbp-15h]
  int i; // [rsp+1Ch] [rbp-14h]
  int j; // [rsp+20h] [rbp-10h]
  int k; // [rsp+24h] [rbp-Ch]

  for ( i = 0; i <= 28; ++i )
  {
    for ( j = 0; j <= 31; j += 8 )
    {
      v3 = 0;
      for ( k = 0; k <= 7; ++k )
      {
        v3 *= 2;
        if ( j + k <= 28 )
          v3 |= a1[29 * i + j + k];
      }
      sprintf(a2, "%02x", v3);
      a2 += 2;
    }
  }
  *a2 = 0;
  return a2;
}
```

It does:

1. add padding to the input string
2. convert to qrcode
3. compress every 8 bit in qrcode to one pixel
4. print the result with some garbage

So we reverse the process:

```python
import numpy as np
from PIL import Image

data = bytes.fromhex(open("output.txt", encoding="utf-8").read())
# strip unused prefix
data = data[7:]

# recover qr code
qrcode = np.zeros((29, 29, 3), dtype=np.uint8)
for i in range(29):
    for j in range(0, 31, 8):
        val = data[i * 4 + j // 8]
        for k in range(8):
            if j + k < 29:
                qrcode[i, j + k] = ((val >> (7 - k)) & 1) * 255

image = Image.fromarray(qrcode)
image.save("result.png")
```

Result:

![](./show-me.png)

Flag: `ASIS{tH3_sEcRe7_FLAG_iZ__QR__CODE!!}`.
