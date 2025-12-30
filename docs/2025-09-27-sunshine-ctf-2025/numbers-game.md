# Numbers Game

```
Welcome to the Numbers Game! You'll need some luck for this one.

    numbers-game

nc chal.sunshinectf.games 25101 
```

Decompile in IDA:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  __int64 v4; // rbx
  __int64 v5; // rbx
  char s[256]; // [rsp+0h] [rbp-120h] BYREF
  __int64 v8; // [rsp+100h] [rbp-20h] BYREF
  __int64 v9; // [rsp+108h] [rbp-18h]

  puts(
    "Let's make a deal! If you can guess the number of fingers I am holding up behind my back, I'll let you have my flag.\x1B[0m");
  puts("\x1B[4mHint: I am polydactyl and have 18,466,744,073,709,551,615 fingers.\x1B[0m");
  v3 = time(0);
  srand(v3);
  v4 = rand();
  v5 = ((__int64)rand() << 31) | v4;
  v9 = v5 | ((__int64)rand() << 62);
  if ( !fgets(s, 256, stdin) )
    puts("\x1B[31mError with input.\x1B[0m");
  __isoc99_sscanf(s, "%llu", &v8);
  if ( v9 == v8 )
    system("cat flag.txt");
  else
    puts("\x1B[31mWRONG!!! Maybe next time?\x1B[0m");
  return 0;
}
```

Since the random seed is `time(0)`, write a program locally to compute the same numbers and compile to `./numbers`:

```c
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>

int main() {
  unsigned int v3 = time(0);
  srand(v3);
  int64_t v4 = rand();
  int64_t v5 = ((int64_t)rand() << 31) | v4;
  int64_t v9 = v5 | ((int64_t)rand() << 62);
  printf("%llu\n", v9);
  return 0;
}
```

Attack:

```python
from pwn import *
import subprocess

# p = process("./numbers-game")
p = remote("chal.sunshinectf.games", 25101)
p.recvuntil(b"fingers.")
s = subprocess.check_output("./numbers")
p.sendline(s)
p.interactive()
```

Flag: `sun{I_KNOW_YOU_PLACED_A_MIRROR_BEHIND_ME}`.
