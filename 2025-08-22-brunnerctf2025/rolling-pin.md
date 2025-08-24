# Rolling Pin

```
Difficulty: Beginner
Author: rvsmvs

The head baker's gone rogue and locked up the recipe for the perfect pastry swirl inside a secret code. Can you knead your way through layers of fluffy obfuscation and figure out the exact mix of bytes to make it rise just right?
```

Decompiled via Ghidra:

```c

/* WARNING: Unknown calling convention */

int main(void)

{
  long lVar1;
  uint8_t uVar2;
  long lVar3;
  long in_FS_OFFSET;
  size_t n;
  size_t i;
  char buf [64];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Roll the dough:");
  lVar3 = fgets(buf,0x40,stdin);
  if (lVar3 != 0) {
    n = strlen(buf);
    if ((n != 0) && (buf[n - 1] == '\n')) {
      n = n - 1;
    }
    if (n == 0x19) {
      for (i = 0; i < 0x19; i = i + 1) {
        uVar2 = rotl(buf[i],(uint)i & 7);
        if (uVar2 != baked[i]) {
          puts("Not quite done yet");
          goto LAB_004012da;
        }
      }
      puts("Good job!");
    }
    else {
      puts("Not quite done yet");
    }
  }
LAB_004012da:
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}


uint8_t rotl(uint8_t x,int k)

{
  int k_local;
  uint8_t x_local;
  
  return (byte)((int)(uint)x >> (8 - (byte)k & 0x1f)) | x << ((byte)k & 0x1f);
}
```

We can reverse the process by replacing `rotl` with `rotr`:

```c
#include <stdio.h>
#include <stdint.h>

uint8_t rotr(uint8_t x, int k) {
  int k_local;
  uint8_t x_local;

  return (uint8_t)((uint8_t)x << (8 - (uint8_t)k & 0x1f)) |
         x >> ((uint8_t)k & 0x1f);
}

uint8_t baked[] = {'b', 0xE4, 0xD5, 's',  0xE6, 0xAC, 0x9C, 0xBD, 'r',
                   '`', 0xD1, 0xA1, 'G',  'f',  0xD7, ':',  'h',  'f',
                   '}', '#',  0x03, 0xAE, 0xD9, '4',  '}'};

int main() {
  for (int i = 0; i < 0x19; i = i + 1) {
    char ch = rotr(baked[i], (uint32_t)i & 7);
    printf("%c", ch);
  }
  return 0;
}
```

Get flag: `brunner{r0t4t3_th3_d0ugh}`
