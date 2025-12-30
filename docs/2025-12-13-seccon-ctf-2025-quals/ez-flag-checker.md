# Ez Flag Checker

Co-authors: @Xyzst @LZDQ

Reverse enginnered by AI:

# Attack Methodology for Ez Flag Checker

## Reverse Engineering Process
1. **Binary Analysis**: The challenge provides a 64-bit ELF binary with debug symbols (not stripped).
2. **Main Function**: The program reads a flag, validates it's 26 characters with format `SECCON{...}`, then encrypts the 18-character inner part using `sigma_encrypt()`.
3. **Encryption Algorithm**: `sigma_encrypt()` implements a simple XOR cipher:
   - Key material: `sigma_words` contains "expand 32-byte k" (ChaCha20 constant)
   - Encryption: `out[i] = (i + key_bytes[i & 0xF]) ^ message[i]`
   - Where `key_bytes` is derived from `sigma_words` (4 little-endian dwords converted to bytes)
4. **Comparison**: Encrypted result is compared against hardcoded `flag_enc` (18 bytes).

## Solution
The encryption is reversible (XOR). Decryption formula:
- `message[i] = (i + key_bytes[i & 0xF]) ^ flag_enc[i]`

Where:
- `flag_enc` = `03 15 13 03 11 55 1f 43 63 61 59 ef bc 10 1f 43 54 a8`
- `key_bytes` derived from "expand 32-byte k":
  - Bytes: `65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b`
  - Repeats every 16 bytes (i & 0xF)

## Decrypted Flag
Inner flag: `flagc<9yYW5k<b19!!`
Full flag: `SECCON{flagc<9yYW5k<b19!!}`

## Verification
A test C program confirms this flag encrypts to the exact `flag_enc` bytes. However, the actual binary rejects this input for unknown reasons (possibly environment or implementation difference).

## Tools Used
- Python for decryption script
- C for verification
- Analysis of assembly code and memory layout

However, the flag is wrong. After debugging, we found that, the encryption key is changed to `expanb 32-byte k` in `_dl_main`. So the correct flag should be `SECCON{flagc29yYW5k<b19!!}`.

Attack script:

```python
#!/usr/bin/env python3

# Encrypted flag from binary
flag_enc = bytes([
    0x03, 0x15, 0x13, 0x03, 0x11, 0x55, 0x1f, 0x43,
    0x63, 0x61, 0x59, 0xef, 0xbc, 0x10, 0x1f, 0x43,
    0x54, 0xa8
])

# sigma_words should be "expand 32-byte k" but there appears to be a bug
# that causes key_bytes[5] to be 0x62 ('b') instead of 0x64 ('d')
# This results in '2' at position 5 instead of '<'
sigma_words = b"expand 32-byte k"

# Reconstruct key_bytes as in sigma_encrypt function
# The function takes 4 dwords from sigma_words and converts to bytes in little-endian
key_bytes = bytearray(24)

# Convert sigma_words to key_bytes (little-endian dwords to bytes)
for i in range(4):
    w = int.from_bytes(sigma_words[i*4:(i+1)*4], 'little')
    key_bytes[4*i] = w & 0xFF
    key_bytes[4*i + 1] = (w >> 8) & 0xFF
    key_bytes[4*i + 2] = (w >> 16) & 0xFF
    key_bytes[4*i + 3] = (w >> 24) & 0xFF

print(f"Key bytes from sigma_words: {key_bytes.hex()}")
print(f"Key bytes length: {len(key_bytes)}")

# The binary appears to have a bug where key_bytes[5] is 0x62 instead of 0x64
# This could be due to an off-by-one error, buffer overflow, or other issue
# For the correct flag, we need key_bytes[5] = 0x62
key_bytes[5] = 0x62  # Fix the bug

print(f"Key bytes with bug fix: {key_bytes.hex()}")

# Decrypt the flag
# out[i] = (i + key_bytes[i & 0xF]) ^ message[i]
# So: message[i] = (i + key_bytes[i & 0xF]) ^ out[i]

decrypted = bytearray(len(flag_enc))
for i in range(len(flag_enc)):
    key_byte = key_bytes[i & 0xF]
    decrypted[i] = (i + key_byte) ^ flag_enc[i]

print(f"Decrypted inner flag: {decrypted}")
print(f"Decrypted inner flag (ascii): {decrypted.decode('ascii', errors='replace')}")

# Full flag
full_flag = f"SECCON{{{decrypted.decode('ascii')}}}"
print(f"Full flag: {full_flag}")
```
