# Plastic Shield

```
OPSec is useless unless you do it correctly.
```

Decompiled via Ghidra:

```c

undefined8 main(void)

{
  size_t sVar1;
  undefined1 ctx [256];
  char local_248 [16];
  char local_238 [32];
  char local_218 [64];
  char local_1d8 [64];
  undefined1 local_198;
  char local_189;
  byte local_188 [64];
  char password [263];
  byte local_41;
  char *decrypted;
  char *local_38;
  ulong local_30;
  size_t password_len;
  ulong i;
  ulong decrypted_len;
  ulong j;
  
  printf("Please enter the password: ");
  __isoc99_scanf("%255s",password);
  password_len = strlen(password);
  local_30 = (password_len * 0x3c) / 100;
  local_189 = password[local_30];
  crypto_blake2b(local_188,0x40,&local_189,1);
  for (j = 0; j < 0x40; j = j + 1) {
    sprintf(local_218 + j * 2,"%02x",(ulong)local_188[j]);
  }
  local_198 = 0;
  local_38 = 
  "713d7f2c0f502f485a8af0c284bd3f1e7b03d27204a616a8340beaae23f130edf65401c1f99fe99f63486a385ccea217"
  ;
  hex_to_bytes(local_218,local_238,0x20);
  hex_to_bytes(local_1d8,local_248,0x10);
  sVar1 = strlen(local_38);
  decrypted_len = sVar1 >> 1;
  decrypted = (char *)malloc(decrypted_len);
  hex_to_bytes(local_38,decrypted,decrypted_len);
  AES_init_ctx_iv(ctx,local_238,local_248);
  AES_CBC_decrypt_buffer(ctx,decrypted,decrypted_len);
  local_41 = decrypted[decrypted_len - 1];
  if ((local_41 < 0x11) && (local_41 != 0)) {
    decrypted_len = decrypted_len - local_41;
  }
  printf("Decrypted text: ");
  for (i = 0; i < decrypted_len; i = i + 1) {
    putchar((uint)(byte)decrypted[i]);
  }
  putchar(10);
  free(decrypted);
  return 0;
}
```

The problem is, the input string of `crypto_blake2b` has only one character:

```c
local_189 = password[local_30];
crypto_blake2b(local_188,0x40,&local_189,1);
```

So we just bruteforce the character until `scriptCTF` is shown:

```python
from pwn import *
elf = ELF("./plastic-shield")
context.binary = elf
context.terminal = ["tmux", "split-w", "-h"]
context(arch='amd64', os='linux', log_level='debug')

for i in range(0x21, 0x80):
    p = process("./plastic-shield")
    p.sendline(bytes([i]))
    line = p.recvline()
    if b"scriptCTF" in line:
        print(line)
        break
```

Get flag: `Please enter the password: Decrypted text: scriptCTF{20_cau541i71e5_d3f3n5es_d0wn}`
