# Easy RE 1 WP

本题是一个简单逆向题，输入一段字符串，经过三个可逆的变换，和一个预设的字符串进行比对，成功则说明输入的是正确的 flag。反编译结果如下：

```c
__int64 __fastcall sub_401785(__int64 a1)
{
  __int64 result; // rax
  char v2; // [rsp+1Fh] [rbp-11h]
  int v3; // [rsp+20h] [rbp-10h]
  unsigned int k; // [rsp+24h] [rbp-Ch]
  int j; // [rsp+28h] [rbp-8h]
  int i; // [rsp+2Ch] [rbp-4h]

  v3 = j_ifunc_417390(a1);
  for ( i = 0; i < v3; ++i )
    *(_BYTE *)(i + a1) ^= 0x42u;
  for ( j = 0; j < v3 / 2; ++j )
  {
    v2 = *(_BYTE *)(j + a1);
    *(_BYTE *)(j + a1) = *(_BYTE *)(v3 - j - 1LL + a1);
    *(_BYTE *)(a1 + v3 - j - 1LL) = v2;
  }
  for ( k = 0; ; ++k )
  {
    result = k;
    if ( (int)k >= v3 )
      break;
    if ( *(char *)((int)k + a1) <= 96 || *(char *)((int)k + a1) > 122 )
    {
      if ( *(char *)((int)k + a1) > 64 && *(char *)((int)k + a1) <= 90 )
        *(_BYTE *)((int)k + a1) = (*(char *)((int)k + a1) - 62) % 26 + 65;
    }
    else
    {
      *(_BYTE *)((int)k + a1) = (*(char *)((int)k + a1) - 94) % 26 + 97;
    }
  }
  return result;
}
```

通过逆向，可知三个可逆的变换为：

1. 逐字节异或 0x42
2. 字符串求倒序
3. 凯撒加密，每个字母旋转加三

编写代码求解：

```c
#include <stdio.h>
#include <string.h>

// Reverse the transformations to find the original flag
void reverse_transform(char *input) {
  int len = strlen(input);

  // Reverse Transformation 3: Caesar cipher -3
  for (int i = 0; i < len; i++) {
    if (input[i] >= 'a' && input[i] <= 'z') {
      input[i] = ((input[i] - 'a' - 3 + 26) % 26) + 'a';
    } else if (input[i] >= 'A' && input[i] <= 'Z') {
      input[i] = ((input[i] - 'A' - 3 + 26) % 26) + 'A';
    }
  }

  // Reverse Transformation 2: Reverse the string (same as forward)
  for (int i = 0; i < len / 2; i++) {
    char temp = input[i];
    input[i] = input[len - i - 1];
    input[len - i - 1] = temp;
  }

  // Reverse Transformation 1: XOR with same pattern (XOR is self-reversible)
  for (int i = 0; i < len; i++) {
    input[i] ^= 0x42;
  }
}

int main() {
  char target[] = "?'/\035&,7-$\0357-;9%#.$"; // The transformed flag

  printf("Target string: %s\n", target);

  // Create a copy to reverse
  char flag[100];
  strcpy(flag, target);

  // Apply reverse transformations
  reverse_transform(flag);

  printf("Original flag: %s\n", flag);

  return 0;
}
```

注：本题是用 DeepSeek 出的。同时，DeepSeek 也能求解出本题：

```
Analysis Summary

The binary main is a 64-bit ELF executable that performs the following
transformations on the input flag:

1. XOR with 0x42: Each character is XORed with 0x42
2. String reversal: The entire string is reversed
3. Caesar cipher transformation:
  - Lowercase letters (a-z): (char - 94) % 26 + 97
  - Uppercase letters (A-Z): (char - 62) % 26 + 65
  - Other characters remain unchanged

The expected result after these transformations is stored at memory address
0x477010 as bytes: 0x3f 0x27 0x2f 0x1d 0x26 0x2c 0x37 0x2d 0x24 0x1d 0x37 0x2d
0x3b 0x39 0x25 0x23 0x2e 0x24

Solution

I wrote a Python script that reverses these transformations and found the flag:

Flag: flag{you_found_me}

The flag has been verified by running it through the original binary, which
outputs "Correct! You found the flag!"

The key functions analyzed were:
- sub_40194E: Main function that reads input and checks the flag
- sub_401785: Transformation function that applies the three operations
- The comparison is done against the hardcoded bytes at 0x477010
```

DeepSeek 生成的求解代码：

```python
#!/usr/bin/env python3

# The binary performs the following transformations on the input:
# 1. XOR each character with 0x42
# 2. Reverse the string
# 3. Apply a Caesar cipher-like transformation:
#    - For lowercase letters (a-z): (char - 94) % 26 + 97
#    - For uppercase letters (A-Z): (char - 62) % 26 + 65
#    - Other characters remain unchanged

# The expected result after transformations is stored at 0x477010
# Bytes: 0x3f 0x27 0x2f 0x1d 0x26 0x2c 0x37 0x2d 0x24 0x1d 0x37 0x2d 0x3b 0x39
# 0x25 0x23 0x2e 0x24

expected = bytes(
    [
        0x3F,
        0x27,
        0x2F,
        0x1D,
        0x26,
        0x2C,
        0x37,
        0x2D,
        0x24,
        0x1D,
        0x37,
        0x2D,
        0x3B,
        0x39,
        0x25,
        0x23,
        0x2E,
        0x24,
    ]
)


def reverse_transform(data):
    # Step 3: Reverse the Caesar cipher
    result = []
    for byte in data:
        if 97 <= byte <= 122:  # lowercase
            # Original: (char - 94) % 26 + 97
            # Reverse: (char - 97 + 94) % 26 + 97
            result.append((byte - 97 + 94) % 26 + 97)
        elif 65 <= byte <= 90:  # uppercase
            # Original: (char - 62) % 26 + 65
            # Reverse: (char - 65 + 62) % 26 + 65
            result.append((byte - 65 + 62) % 26 + 65)
        else:
            result.append(byte)

    # Step 2: Reverse the string
    result = result[::-1]

    # Step 1: XOR with 0x42
    result = [byte ^ 0x42 for byte in result]

    return bytes(result)


flag = reverse_transform(expected)
print(f"Flag: {flag.decode()}")
```

目前 AI 大模型对 Reverse 题目的求解能力是比较强的（相比其他类型的题目），建议初学者在学习 Reverse 的过程中，学会如何利用大模型来解决 Reverse 题目。
