# butterfly

合作者：DeepSeek

反编译后找到核心代码：

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v3; // cl
  char v4; // cl
  const char *v6; // r14
  const char *v7; // r13
  __int64 v8; // rax
  char v9; // cl
  __int64 v10; // r12
  __int64 size; // rbx
  __int64 v12; // rax
  __m64 *v13; // rbp
  __int64 v14; // r15
  char v15; // cl
  char v16; // cl
  __m64 *v17; // rax
  __m64 v18; // mm0
  __m64 v19; // mm2
  char v20; // cl
  char v21; // cl
  char v22; // cl
  _OWORD v23[2]; // [rsp+0h] [rbp-158h] BYREF
  __m64 v24[39]; // [rsp+20h] [rbp-138h] BYREF

  if ( argc != 3 )
  {
    printf(2, (unsigned int)"Usage: %s <input_file> <output_file>\n", (unsigned int)*argv, v3);
    printf(2, (unsigned int)"Example: %s plaintext.txt encoded.dat\n", (unsigned int)*argv, v4);
    return 1;
  }
  v6 = argv[1];
  v7 = argv[2];
  v8 = open(v6, "rb");
  v10 = v8;
  if ( !v8 )
  {
    printf(2, (unsigned int)"Error: Cannot open file %s\n", (_DWORD)v6, v9);
    return 1;
  }
  fseek(v8, 0, 2);
  size = ftell(v10);
  fseek(v10, 0, 0);
  v12 = malloc(size + 8);
  v13 = (__m64 *)v12;
  if ( !v12 )
  {
    fclose(v10);
    sub_4774A0("Error: Memory allocation failed");
    return 1;
  }
  v14 = fread(v12, size + 8, 1, size, v10);
  fclose(v10);
  if ( size != v14 )
  {
    sub_412CF0(v13);
    sub_4774A0("Error: File read failed");
    return 1;
  }
  *(__int16 *)((char *)v13->m64_i16 + size) = size;
  v23[0] = _mm_loadu_si128((const __m128i *)"MMXEncode2024");
  v23[1] = _mm_loadu_si128((const __m128i *)"coding file: %s\n");
  printf(2, (unsigned int)"Encoding file: %s\n", (_DWORD)v6, v15);
  printf(2, (unsigned int)"Original size: %zu bytes\n", size, v16);
  v24[0] = *(__m64 *)&v23[0];
  if ( (int)size > 7 )
  {
    v17 = v13;
    do
    {
      v18 = _m_pxor((__m64)v17->m64_u64, v24[0]);
      v19 = _m_por(_m_psrlwi(v18, 8u), _m_psllwi(v18, 8u));
      v17->m64_u64 = (unsigned __int64)_m_paddb(_m_por(_m_psllqi(v19, 1u), _m_psrlqi(v19, 0x3Fu)), v24[0]);
      if ( &v13[(unsigned int)(size - 1) >> 3] == v17 )
        break;
      ++v17;
    }
    while ( &v13[((unsigned int)(size - 8) >> 3) + 1] != v17 );
  }
  _m_empty();
  if ( (unsigned int)write_to_file(v7, v13, size) )
  {
    printf(2, (unsigned int)"Successfully encoded to: %s\n", (_DWORD)v7, v20);
    printf(2, (unsigned int)"Encoded size: %zu bytes\n", size, v21);
    snprintf((unsigned int)v24, 256, 2, 256, (unsigned int)"%s.key", (_DWORD)v7, v23[0]);
    if ( (unsigned int)write_to_file(v24, v23, 32) )
      printf(2, (unsigned int)"Key saved to: %s\n", (unsigned int)v24, v22);
  }
  sub_412CF0(v13);
  return 0;
}
```

让 DeepSeek 生成一份解题的代码：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mmintrin.h>

void decode_data(unsigned char *data, size_t size) {
    __m64 key = _mm_set_pi64x(*(long long*)"MMXEncode2024");

    if (size > 7) {
        __m64 *ptr = (__m64 *)data;
        size_t qword_count = size / 8;

        for (size_t i = 0; i < qword_count; i++) {
            __m64 encrypted = ptr[i];

            // Reverse the encoding process
            // Original encoding: data = _m_paddb(_m_por(_m_psllqi(rotated, 1u), _m_psrlqi(rotated, 0x3Fu)), key)
            // where rotated = _m_por(_m_psrlwi(xored, 8u), _m_psllwi(xored, 8u))
            // and xored = _m_pxor(data, key)

            // Step 1: Reverse _m_paddb
            __m64 step1 = _m_psubb(encrypted, key);

            // Step 2: Reverse the bit rotation
            // Original: rotated = (v30 << 1) | (v30 >> 63)
            // Reverse: v30 = (step1 >> 1) | (step1 << 63)
            __m64 step2 = _m_por(_m_psrlqi(step1, 1u), _m_psllqi(step1, 0x3Fu));

            // Step 3: Reverse the byte swap
            // Original: rotated = (xored >> 8) | (xored << 8)
            // Reverse: xored = (step2 << 8) | (step2 >> 8)
            __m64 step3 = _m_por(_m_psllwi(step2, 8u), _m_psrlwi(step2, 8u));

            // Step 4: Reverse the XOR
            __m64 decrypted = _m_pxor(step3, key);

            ptr[i] = decrypted;
        }
    }
    _m_empty();
}

int main() {
    FILE *f = fopen("encode.dat", "rb");
    if (!f) {
        printf("Cannot open encode.dat\n");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);

    printf("Encoded size: %zu bytes\n", size);

    // Decode the data
    decode_data(data, size);

    // Print the decoded data
    printf("Decoded data:\n");
    for (size_t i = 0; i < size; i++) {
        printf("%c", data[i]);
    }
    printf("\n");

    free(data);
    return 0;
}
```

运行后，给出结果：

```
Encoded size: 36 bytes
Decoded data:
flag{butter_fly_mmx_encode_7778167}
```
