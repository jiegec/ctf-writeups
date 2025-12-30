# Plastic Shield 2

```
Ashray Shah

Okay! Fixed last time's issue. Seriously though, I swear this one is unbreakable.
```

I did not solve it in the competition.

The attachment decompiled via Ghidra:

```c

undefined8 main(void)

{
  long lVar1;
  size_t sVar2;
  undefined1 ctx [256];
  char iv [16];
  char local_23e [2];
  char local_23c [3];
  undefined1 local_239;
  char key [32];
  char blake2b_out_hex [129];
  byte blake2b_out [64];
  char password [263];
  byte local_41;
  void *decrypted;
  char local_31;
  char *ciphertext;
  size_t password_len;
  ulong local_20;
  ulong decrypted_len;
  ulong local_10;
  
  printf("Please enter the password: ");
  __isoc99_scanf("%255s",password);
  password_len = strlen(password);
  crypto_blake2b(blake2b_out,0x40,password,password_len);
  for (local_10 = 0; local_10 < 0x40; local_10 = local_10 + 1) {
    sprintf(blake2b_out_hex + local_10 * 2,"%02x",(ulong)blake2b_out[local_10]);
  }
  blake2b_out_hex[0x80] = '\0';
  ciphertext = "e2ea0d318af80079fb56db5674ca8c274c5fd0e92019acd01e89171bb889f6b1";
  memset(key,0,0x20);
  strncpy(local_23c,blake2b_out_hex + 0x7d,3);
  local_239 = 0;
  hex_to_bytes(local_23c,key,1);
  local_23e[0] = blake2b_out_hex[0x7f];
  local_23e[1] = '\0';
  lVar1 = strtol(local_23e,(char **)0x0,0x10);
  local_31 = (char)lVar1;
  key[1] = local_31 << 4;
  memset(iv,0,0x10);
  hex_to_bytes(local_23c,iv,1);
  iv[1] = local_31 << 4;
  sVar2 = strlen(ciphertext);
  decrypted_len = sVar2 >> 1;
  decrypted = malloc(decrypted_len);
  hex_to_bytes(ciphertext,decrypted,decrypted_len);
  AES_init_ctx_iv(ctx,key,iv);
  AES_CBC_decrypt_buffer(ctx,decrypted,decrypted_len);
  local_41 = *(byte *)((long)decrypted + (decrypted_len - 1));
  if ((local_41 < 0x11) && (local_41 != 0)) {
    decrypted_len = decrypted_len - local_41;
  }
  printf("Decrypted text: ");
  for (local_20 = 0; local_20 < decrypted_len; local_20 = local_20 + 1) {
    putchar((uint)*(byte *)(local_20 + (long)decrypted));
  }
  putchar(10);
  free(decrypted);
  return 0;
}
```

We can see that the key and iv have only the first two bytes written, and they are the same. So we just bruteforce them.

Initially, I wrote this python script, but got nothing:

```python
from Cryptodome.Cipher import AES

ciphertext = bytes.fromhex("e2ea0d318af80079fb56db5674ca8c274c5fd0e92019acd01e89171bb889f6b1")

for byte1 in range(256):
    for byte2 in range(256):
        key = bytes([byte1, byte2] + [0] * 30)
        iv = bytes([byte1, byte2] + [0] * 14)
        decrypt = AES.new(key, AES.MODE_CBC, iv)
        plaintext = decrypt.decrypt(ciphertext)
        if b"script" in plaintext:
            print(plaintext)
```

I even validated that, under the same key and iv, the decrypted text is the same as the `plastic-shield-2` binary in the attachment.

After the competition, after seeing others' writeup, e.g. <https://github.com/amritansha82/ScriptCTF-20225-Writeups/blob/c76393a94ba2c6fcf0e0ac1521d066795f056132/plastic_shield_2.md>, I realized that in order to get the flag, the key length is 16 bytes (AES-128), instead of 32 bytes (AES-256)! The [source code in the official writeup](https://github.com/scriptCTF/scriptCTF2025-OfficialWriteups/blob/a7811d8fabf9fc1e48ce48cfbcc6bd29a65b783f/Rev/Plastic%20Shield%202/src/aes.h#L27-L42) verifies this:

```c
#define AES128 1
//#define AES192 1
#define AES256 1

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only

#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
#else
    #define AES_KEYLEN 16   // Key length in bytes
    #define AES_keyExpSize 176
#endif
```

Now bruteforcing works:

```python
from Cryptodome.Cipher import AES

ciphertext = bytes.fromhex("e2ea0d318af80079fb56db5674ca8c274c5fd0e92019acd01e89171bb889f6b1")

for byte1 in range(256):
    for byte2 in range(256):
        key = bytes([byte1, byte2] + [0] * 14)
        iv = bytes([byte1, byte2] + [0] * 14)
        decrypt = AES.new(key, AES.MODE_CBC, iv)
        plaintext = decrypt.decrypt(ciphertext)
        if b"script" in plaintext:
            print(plaintext)
```

Get flag: `scriptCTF{00p513_n07_4641n!}`

I am unsure whether this is intended by the author (AES-128 vs AES-256 and discrepancy between binary and actual flag)... So essentially you cannot find the correct password given the binary.
