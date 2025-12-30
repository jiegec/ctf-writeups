# blank

```
Why should we trust the kernel mode Syscalls to handle the errors ?

Author : N!L
```

Writeup written by AI agent:

# Reverse Engineering CTF Challenge Solution

## Challenge Analysis
The binary is a simple reverse engineering challenge that XORs encrypted data segments with corresponding pad values to reveal a flag.

## Binary Structure
- Main function loops 10 times (NUM_SEGMENTS = 10)
- For each iteration:
  1. XORs 32 bytes from cipher_segments[i] with pads[i]
  2. Writes result to file descriptor 5
  3. Reads 1 byte from file descriptor 7
  4. Writes "OK" to file descriptor 8

## Data Locations
- cipher_segments: virtual address 0x4aa100, file offset 0xa9100
- pads: virtual address 0x4aa240, file offset 0xa9240
- NUM_SEGMENTS: 10 (stored at 0x4aa0e0)

## Solution Approach
1. Extract cipher_segments and pads arrays from the binary
2. XOR corresponding segments (cipher[i] ^ pads[i])
3. Remove null bytes and decode as UTF-8
4. Concatenate all decoded segments

## Flag Extraction
The flag is revealed by XORing each 32-byte segment:
- Segment 0: `nexus{`
- Segment 1: `th3_f`
- Segment 2: `l4g_w1ll`
- Segment 3: `_r3ve4l`
- Segment 4: `_1ts3l`
- Segment 5: `f_wh3n`
- Segment 6: `_y0u_`
- Segment 7: `st0p_`
- Segment 8: `look`
- Segment 9: `1ng}`

Complete flag: nexus{th3_fl4g_w1ll_r3ve4l_1ts3lf_wh3n_y0u_st0p_look1ng}

## Testing
The binary can be tested with pipe redirection:
```bash
./blank 5>&1 7</dev/null 8>&1
```

This outputs the flag segments interleaved with "OK" messages.

## Tools Used
- Python for data extraction and XOR operations
- ELF analysis tools (readelf) for section mapping
