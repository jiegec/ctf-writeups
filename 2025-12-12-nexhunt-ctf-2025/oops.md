# oops!

```
The binary prints nothing useful, and I might have forgotten to remove some symbols when compiling… Not sure if that actually matters though.

Author : N!L
```

Writeup written by AI agent:

# Solution for reverse-oops! CTF Challenge

## Analysis
The binary contains encrypted data in the `synt` array (75 bytes). The challenge hint mentions "I *might* have forgotten to remove some symbols when compiling" - referring to the symbols `junk`, `blob`, `synt`, and `temp_key` that are visible in the binary.

## Solution Steps
1. Extract the `synt` array data from the binary (75 bytes starting at address 0x4060)
2. Notice the string "S0E=" in the strings output, which is base64 for "KA"
3. XOR the `synt` data with repeating key "KA" (0x4b, 0x41)
4. This reveals the flag

## Decryption Code
```python
synt = bytes([0x25, 0x24, 0x33, 0x34, 0x38, 0x3a, 0x7c, 0x29, 0x78, 0x1e, 0x28, 0x71, 0x2f, 0x72, 0x14, 0x38, 0x7b, 0x34, 0x14, 0x33, 0x78, 0x75, 0x2f, 0x1e, 0x39, 0x72, 0x2d, 0x2d, 0x78, 0x22, 0x7c, 0x74, 0x14, 0x76, 0x23, 0x72, 0x14, 0x2c, 0x7a, 0x2f, 0x2f, 0x1e, 0x32, 0x71, 0x3e, 0x1e, 0x28, 0x75, 0x39, 0x33, 0x32, 0x1e, 0x25, 0x71, 0x7c, 0x1e, 0x7c, 0x29, 0x78, 0x1e, 0x3c, 0x71, 0x39, 0x2d, 0x2f, 0x1e, 0x32, 0x71, 0x3e, 0x1e, 0x2d, 0x72, 0x7f, 0x33, 0x36])
key = b'KA'
decoded = bytes([synt[i] ^ key[i % len(key)] for i in range(len(synt))])
print(decoded.decode('ascii'))
```

## Flag
`nexus{7h3_c0d3_y0u_r34d_r3fl3c75_7h3_m1nd_y0u_c4rry_n07_7h3_w0rld_y0u_f34r}`

## Notes
- The `junk`, `blob`, and `temp_key` arrays appear to be red herrings
- The main function only prints "oops! nothing interesting here..." to misdirect
- The actual flag is stored encrypted in the `synt` array
- The key "KA" is hinted at via base64 string "S0E=" in the binary strings
