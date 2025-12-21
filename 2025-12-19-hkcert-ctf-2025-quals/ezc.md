# ezc

Decompile the attachment:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // ebx
  __pid_t v4; // eax
  void *v5; // rsp
  void *v7; // rsp
  _QWORD v8[7]; // [rsp+8h] [rbp-4A0h] BYREF
  unsigned __int64 j; // [rsp+40h] [rbp-468h]
  size_t v10; // [rsp+48h] [rbp-460h]
  unsigned __int64 i; // [rsp+50h] [rbp-458h]
  __int64 v12; // [rsp+58h] [rbp-450h]
  _QWORD *v13; // [rsp+60h] [rbp-448h]
  __int64 v14; // [rsp+68h] [rbp-440h]
  void *s1; // [rsp+70h] [rbp-438h]
  char s[1032]; // [rsp+78h] [rbp-430h] BYREF
  unsigned __int64 v17; // [rsp+480h] [rbp-28h]

  v17 = __readfsqword(0x28u);
  v3 = time(0);
  v4 = getpid();
  srand((v4 ^ v3) % 0x14);
  v12 = 35;
  v8[4] = 36;
  v8[5] = 0;
  v8[2] = 36;
  v8[3] = 0;
  v5 = alloca(48);
  v13 = v8;
  for ( i = 0; i < 0x24; ++i )
    *((_BYTE *)v13 + i) = rand();
  printf("Enter your guess (exactly %zu bytes): ", 0x24u);
  if ( fgets(s, 1024, stdin) )
  {
    v10 = strlen(s);
    if ( v10 && s[v10 - 1] == 10 )
      s[--v10] = 0;
    if ( v10 == 36 )
    {
      v14 = 35;
      v8[0] = 36;
      v8[1] = 0;
      v7 = alloca(48);
      s1 = v8;
      for ( j = 0; j < 0x24; ++j )
        *((_BYTE *)s1 + j) = *((_BYTE *)v13 + j) ^ s[j];
      if ( !memcmp(s1, &cipher, 0x24u) )
        puts("Correct! Your input is the plaintext.");
      else
        puts("Incorrect.");
      return 0;
    }
    else
    {
      printf("Wrong length: expected %zu, got %zu\n", 0x24u, v10);
      return 1;
    }
  }
  else
  {
    fwrite("No input\n", 1u, 9u, stderr);
    return 1;
  }
}
```

Based on a random seed, it generates random array and XOR it with input. The result is compared with the `cipher` array. Since the seed is small, we can simply bruteforce it:

```python
#!/usr/bin/env python3
import subprocess
import time
import os
import sys

# Cipher data from binary
cipher = bytes(
    [
        0x1F,
        0xC9,
        0xED,
        0x29,
        0xA6,
        0xFE,
        0x44,
        0xEE,
        0x82,
        0x45,
        0xE9,
        0xD8,
        0x7F,
        0x42,
        0x10,
        0xE0,
        0xBB,
        0x4B,
        0xD0,
        0x05,
        0x4C,
        0x76,
        0x90,
        0xCB,
        0x48,
        0x9C,
        0x7A,
        0xA9,
        0xF0,
        0x33,
        0x55,
        0x25,
        0x64,
        0x88,
        0x3D,
        0xF7,
    ]
)


def generate_random_bytes(seed, count=36):
    """Generate random bytes using C rand() with given seed"""
    import ctypes
    import ctypes.util

    # Load libc
    libc = ctypes.CDLL(ctypes.util.find_library("c"))

    # Seed rand
    libc.srand(seed)

    # Generate random bytes (rand() returns int between 0 and RAND_MAX)
    result = bytearray()
    for _ in range(count):
        rand_val = libc.rand() & 0xFF  # Take only lower byte
        result.append(rand_val)

    return bytes(result)


def brute_force():
    """Brute force all 20 possible seeds"""
    print("Brute forcing all 20 possible seeds...")

    for seed in range(20):
        # Generate random bytes for this seed
        random_bytes = generate_random_bytes(seed)

        # Calculate plaintext: cipher XOR random_bytes
        plaintext = bytes([cipher[i] ^ random_bytes[i] for i in range(36)])

        # Check if plaintext looks like printable ASCII/flag
        # Flag format might be hkcert25{...} or similar
        try:
            plaintext_str = plaintext.decode("ascii")
            # Check if it's mostly printable
            if all(32 <= c <= 126 for c in plaintext):
                print(f"\nSeed {seed}: {plaintext_str}")

                # Check for common flag patterns
                if (
                    b"hkcert" in plaintext.lower()
                    or b"flag" in plaintext.lower()
                    or b"{" in plaintext
                ):
                    print(f"*** POTENTIAL FLAG FOUND ***")
                    return seed, plaintext
        except UnicodeDecodeError:
            # Not ASCII, skip
            pass

    return None, None


if __name__ == "__main__":
    print("=== ezc Challenge Solver ===")
    print(f"Cipher length: {len(cipher)} bytes")

    # First, brute force to find the correct seed
    seed, plaintext = brute_force()

    if seed is not None:
        print(f"\nFound potential solution:")
        print(f"  Seed: {seed}")
        print(f"  Plaintext: {plaintext}")
        print(f"  Plaintext (hex): {plaintext.hex()}")
```
