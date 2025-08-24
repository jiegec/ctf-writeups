# Grandma's Predictable Cookies

```
Difficulty: Easy-Medium
Author: H4N5

Grandma encrypted her secret cookie recipe using her "special ingredient" a random number generator seeded with the exact time she baked it.

She thought it was uncrackable. But little did she know: Using the same oven clock every time makes your cookies easy to reverse-engineer.

Can you recover her delicious secret?
```

Attachment:

```
Encrypted flag: 3ec63cc41f1ac1980651726ab3ce2948882b879c19671269963e39103c83ebd6ef173d60c76ee5
Encryption time (approx): 1755860000
```

Decompiled via Ghidra:

```c

/* WARNING: Unknown calling convention */

int main(void)

{
  byte bVar1;
  long lVar2;
  int iVar3;
  FILE *__stream;
  size_t flag_len;
  time_t tVar4;
  char *pcVar5;
  char *pcVar6;
  char *pcVar7;
  char *pcVar8;
  char temp [8];
  char flag [256];
  int r;
  uchar[0] *encrypted;
  int approx;
  time_t seed_time;
  size_t len;
  FILE *f;
  size_t i_2;
  size_t i_1;
  int i;
  
  temp[0] = -0x58;
  temp[1] = '\x12';
  temp[2] = '@';
  temp[3] = '\0';
  temp[4] = '\0';
  temp[5] = '\0';
  temp[6] = '\0';
  temp[7] = '\0';
  __stream = fopen("flag.txt","rb");
  if (__stream == (FILE *)0x0) {
    temp[0] = -0x43;
    temp[1] = '\x12';
    temp[2] = '@';
    temp[3] = '\0';
    temp[4] = '\0';
    temp[5] = '\0';
    temp[6] = '\0';
    temp[7] = '\0';
    perror("Error opening flag.txt");
    iVar3 = 1;
  }
  else {
    temp[0] = -0x19;
    temp[1] = '\x12';
    temp[2] = '@';
    temp[3] = '\0';
    temp[4] = '\0';
    temp[5] = '\0';
    temp[6] = '\0';
    temp[7] = '\0';
    flag_len = fread(flag,1,0xff,__stream);
    temp[0] = -9;
    temp[1] = '\x12';
    temp[2] = '@';
    temp[3] = '\0';
    temp[4] = '\0';
    temp[5] = '\0';
    temp[6] = '\0';
    temp[7] = '\0';
    fclose(__stream);
    flag[flag_len] = '\0';
    builtin_strncpy(temp,"\x12\x13@",4);
    temp[4] = '\0';
    temp[5] = '\0';
    temp[6] = '\0';
    temp[7] = '\0';
    tVar4 = get_current_time_danish();
    builtin_strncpy(temp,"N\x13@",4);
    temp[4] = '\0';
    temp[5] = '\0';
    temp[6] = '\0';
    temp[7] = '\0';
    srand((uint)tVar4);
    for (i = 0; i < 1000; i = i + 1) {
      builtin_strncpy(temp,"\\\x13@",4);
      temp[4] = '\0';
      temp[5] = '\0';
      temp[6] = '\0';
      temp[7] = '\0';
      rand();
    }
    lVar2 = ((flag_len + 0xf) / 0x10) * -0x10;
    for (i_1 = 0; i_1 < flag_len; i_1 = i_1 + 1) {
      pcVar5 = flag + lVar2 + -8;
      pcVar5[0] = -0x52;
      pcVar5[1] = '\x13';
      pcVar5[2] = '@';
      pcVar5[3] = '\0';
      pcVar5[4] = '\0';
      pcVar5[5] = '\0';
      pcVar5[6] = '\0';
      pcVar5[7] = '\0';
      iVar3 = rand();
      flag[i_1 + lVar2] = flag[i_1] ^ (byte)(iVar3 % 0x100);
    }
    pcVar6 = flag + lVar2 + -8;
    builtin_strncpy(flag + lVar2 + -8,"\x05\x14@",4);
    pcVar6[4] = '\0';
    pcVar6[5] = '\0';
    pcVar6[6] = '\0';
    pcVar6[7] = '\0';
    printf("Encrypted flag: ");
    for (i_2 = 0; i_2 < flag_len; i_2 = i_2 + 1) {
      bVar1 = flag[i_2 + lVar2];
      pcVar7 = flag + lVar2 + -8;
      builtin_strncpy(flag + lVar2 + -8,"1\x14@",4);
      pcVar7[4] = '\0';
      pcVar7[5] = '\0';
      pcVar7[6] = '\0';
      pcVar7[7] = '\0';
      printf("%02x",(ulong)bVar1);
    }
    pcVar8 = flag + lVar2 + -8;
    builtin_strncpy(flag + lVar2 + -8,"T\x14@",4);
    pcVar8[4] = '\0';
    pcVar8[5] = '\0';
    pcVar8[6] = '\0';
    pcVar8[7] = '\0';
    printf("\nEncryption time (approx): %ld\n",(ulong)(uint)((int)(tVar4 / 10000) * 10000));
    iVar3 = 0;
  }
  return iVar3;
}
```

The code essentially:

1. `srand` using a time between 1755860000 and 1755870000
2. `rand()` for 1000 times
3. xor each byte of flag with `rand() % 0x100`

So we just enumerate the seed, and xor the flag out to find the correct flag:

```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main() {
  const char *encrypted = "3ec63cc41f1ac1980651726ab3ce2948882b879c19671269963e"
                          "39103c83ebd6ef173d60c76ee5";
  uint8_t output[256];
  char flag[256];
  char buffer[256];
  int len = strlen(encrypted);
  for (int i = 0; i < len; i += 2) {
    char temp[3] = {encrypted[i], encrypted[i + 1], '\0'};
    sscanf(temp, "%x", &output[i / 2]);
  }

  // enumerate seed
  for (int seed = 1755860000; seed < 1755870000; seed++) {
    srand(seed);
    // decrypt
    for (int i = 0; i < 1000; i = i + 1) {
      rand();
    }
    for (int i = 0; i < len / 2; i++) {
      flag[i] = output[i] ^ (rand() % 0x100);
    }
    flag[len / 2] = 0;
    if (flag[0] == 'b' && flag[1] == 'r') {
      printf("%s\n", flag);
    }
  }
  return 0;
}
```

Get flag: `brunner{t1me_wr4p_prng_1s_pred1ct4ble}`
