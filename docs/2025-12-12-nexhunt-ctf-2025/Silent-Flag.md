# Silent Flag

```
A smart contract emitted an event containing unknown data. Recover the original value.

Author: R4Y4N3
```

Writeup written by AI agent:

# Silent Flag Challenge Solution

## Challenge Analysis
This is a blockchain smart contract challenge where a `Stored(bytes32 id, bytes data)` event was emitted with:

- Event signature: `Stored(bytes32,bytes)` (topic0: 0x2b017342b91efedb50bcabb8f1d8e8b6e6ad1dc391c876174642e80868b896ed)
- Indexed parameter `id`: 0x1337 (topic1)
- Data: ABI-encoded bytes data

## Solution Steps

1. **Extract the encoded data**: The `data` file contains ABI-encoded bytes:
   ```
   0x0000000000000000000000000000000000000000000000000000000000000020  # offset (32 bytes)
   0x000000000000000000000000000000000000000000000000000000000000001c  # length (28 bytes)
   0x59524f42444c6f07656803757e68730474077306797068050705024a00000000  # actual data (28 bytes) + padding
   ```
2. **Decode ABI encoding**: Extract the actual 28-byte data:
   `59524f42444c6f07656803757e68730474077306797068050705024a`
3. **Analyze the encryption**: The data appears to be encrypted. Given the challenge name "Silent Flag" and the `id` value `0x1337`, we suspect XOR encryption.
4. **Try XOR decryption**: XOR each byte with `0x37` (the lower byte of `0x1337`):
   ```
   Encrypted: 59 52 4f 42 44 4c 6f 07 65 68 03 75 7e 68 73 04 74 07 73 06 79 70 68 05 07 05 02 4a
   XOR 0x37:  6e 65 78 75 73 7b 58 30 52 5f 34 42 49 5f 44 33 43 30 44 31 4e 47 5f 32 30 32 35 7d
   ASCII:     n  e  x  u  s  {  X  0  R  _  4  B  I  _  D  3  C  0  D  1  N  G  _  2  0  2  5  }
   ```

5. **Recover the flag**: `nexus{X0R_4BI_D3C0D1NG_2025}`

## Attack Summary
The flag was XOR-encrypted with key `0x37` (the lower byte of the event's `id` parameter `0x1337`). The solution involves:

1. Parsing the ABI-encoded event data
2. Recognizing XOR encryption pattern
3. Using `0x37` as the XOR key to decrypt
4. Recovering the original flag

## Tools Used

- Python for data analysis and XOR decryption
- Basic understanding of Ethereum ABI encoding for events
- XOR cryptanalysis
