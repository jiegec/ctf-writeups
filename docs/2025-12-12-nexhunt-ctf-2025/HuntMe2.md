# HuntMe2

```
The trail doesn’t stay still. The forest shifts, and the signs no longer speak plainly. What was once hidden in plain sight is now layered behind changing patterns.

Author : N!L
```

Attack script written by AI agent:

```python
#!/usr/bin/env python3

# Data from the binary
byte_402060 = [
    0xf8, 0x98, 0x76, 0xfb, 0xc9, 0x0a, 0x03, 0x0d,
    0x44, 0x3d, 0x6b, 0xa6, 0xc3, 0x25, 0xa8, 0x60,
    0xfb, 0x57, 0x6c, 0xf3, 0xa1, 0xf0, 0xcf, 0x61,
    0xe6, 0xe4, 0x45, 0x16, 0x0e, 0x18, 0x3e, 0x27
]

# The arrays at unk_402020 (5 arrays of 7 bytes each based on the code)
# From address 0x402020, we have data. Looking at the code, v2[0] = &unk_402020,
# v2[1] = &unk_402027, v2[2] = &unk_40202E, v2[3] = &unk_402035, v2[4] = &unk_40203C
# So each is 7 bytes apart (0x402027 - 0x402020 = 7)

data_at_402020 = [
    0xa8, 0xc5, 0x83, 0xa0, 0x42, 0x2c, 0x01,  # array 0
    0xcb, 0x32, 0x20, 0xf3, 0xcf, 0x65, 0xbc,  # array 1  
    0x13, 0x79, 0xb2, 0x29, 0x74, 0x61, 0xe7,  # array 2
    0xa7, 0x68, 0x76, 0x0a, 0x4e, 0x39, 0x43,  # array 3
    0xf1, 0xcd, 0x12, 0xb2, 0x7d, 0x0b, 0x2d   # array 4
]

def sub_401201(a1, a2):
    # return (unsigned __int8)((61 * a2) ^ ((unsigned __int8)((8 * a1) ^ a1) >> 5) ^ (8 * a1) ^ a1);
    temp = ((8 * a1) ^ a1) & 0xFF
    return ((61 * a2) ^ (temp >> 5) ^ temp) & 0xFF

def sub_401239(a1):
    # a1 is the index (0-31)
    v6 = 0
    arrays = []
    for i in range(5):
        arrays.append(data_at_402020[i*7:(i+1)*7])
    
    for i in range(5):
        v4 = arrays[i]  # pointer to array
        v3 = (a1 * (i + 1) + i * i + 3) % 7
        v6 ^= v4[v3]
        v6 = ((2 * v6) | (v6 >> 7)) & 0xFF
    
    return sub_401201(v6, a1)

def compute_target():
    # We need to find input[i] such that: sub_401239(i) ^ input[i] == byte_402060[i]
    # So input[i] = sub_401239(i) ^ byte_402060[i]
    flag = []
    for i in range(32):
        val = sub_401239(i)
        flag_char = val ^ byte_402060[i]
        flag.append(flag_char)
    
    return bytes(flag)

if __name__ == "__main__":
    flag = compute_target()
    print(f"Flag: {flag}")
    print(f"Flag (string): {flag.decode('ascii', errors='ignore')}")
    
    # Test by running through the algorithm
    print("\nTesting...")
    for i in range(32):
        val = sub_401239(i)
        computed = val ^ flag[i]
        if computed != byte_402060[i]:
            print(f"Mismatch at index {i}: {computed:02x} != {byte_402060[i]:02x}")
        else:
            print(f"Index {i}: OK")
```

Writeup written by AI agent:

# HuntMe2 CTF Challenge Solution

## Challenge Analysis
The binary `HuntMe2` is a 64-bit ELF executable that validates a 32-character input flag. The validation algorithm involves:

1. **Input Length Check**: The input must be exactly 32 characters.
2. **Complex Transformation**: Each character at position `i` (0-31) undergoes a transformation through `sub_401239(i)`.
3. **XOR Comparison**: The transformed value is XORed with the input character and compared against a hardcoded byte array `byte_402060`.

## Algorithm Details

### Main Validation (sub_40132A)
- Checks input length == 32
- Calls `sub_401176()` (doesn't affect validation, just computes a value)
- For each position `i` (0-31):
    - Computes `sub_401239(i)`
    - Requires: `sub_401239(i) ^ input[i] == byte_402060[i]`
    - Therefore: `input[i] = sub_401239(i) ^ byte_402060[i]`

### Transformation Function (sub_401239)
Takes index `i` and returns a byte:

1. Uses 5 arrays of 7 bytes each starting at `0x402020`
2. For each array `j` (0-4):
    - Computes index: `(i * (j+1) + j*j + 3) % 7`
    - XORs the byte at that index into accumulator `v6`
    - Rotates `v6` left by 1 bit: `v6 = (2 * v6) | (v6 >> 7)`
3. Passes result through `sub_401201(v6, i)`

### Final Transformation (sub_401201)

- `return (61 * i) ^ (((8 * v6) ^ v6) >> 5) ^ ((8 * v6) ^ v6)`

## Solution Approach
The solution involves:

1. Extracting the hardcoded data from the binary:
    - `byte_402060` (32 bytes): target XOR results
    - Arrays at `0x402020` (35 bytes, organized as 5x7 arrays)
2. Implementing the transformation algorithm in Python
3. Computing the required input: `input[i] = sub_401239(i) ^ byte_402060[i]`

## Flag
`nexus{f0ll0w_7h3_ch4ng1ng_7r41l}`

## How to Test
```bash
echo -n "nexus{f0ll0w_7h3_ch4ng1ng_7r41l}" | ./HuntMe2
```
Output: "You adapt. The hunt continues."

## Tools Used
- Python for implementing the reverse algorithm
- Standard Linux tools (file, strings, etc.)
