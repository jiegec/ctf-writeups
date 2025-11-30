# Easy Random 1 WP

附件：

```c
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
  setvbuf(stdout, NULL, _IONBF, 0);

  unsigned int seed;
  FILE *fp = fopen("/dev/urandom", "rb");
  fread(&seed, 3, 1, fp);
  srand(seed);

  while (1) {
    printf("Actions: (1) play a random guess game (2) guess the flag\n");
    printf("Please input action:");
    int action = 0;
    scanf("%d", &action);
    if (action == 1) {
      int number = rand() % 65536;
      while (1) {
        printf("Enter your guess:");
        int guess = 0;
        scanf("%d", &guess);
        if (guess > number) {
          printf("Bigger\n");
        } else if (guess < number) {
          printf("Smaller\n");
        } else {
          printf("You win!\n");
          break;
        }
      }
    } else if (action == 2) {
      char *flag = getenv("GZCTF_FLAG");
      if (!flag) {
        flag = "flag{fake_flag_for_testing}";
      }
      unsigned long len = strlen(flag);
      printf("Guess the flag:\n");
      for (unsigned long i = 0; i < len; i++) {
        printf("%02X", (uint8_t)flag[i] ^ (uint8_t)rand());
      }
      printf("\n");
      break;
    }
  }
  return 0;
}
```

本题攻击的是 C 标准库（glibc）的随机数生成器，它的弱点在于 seed 的空间比较小，本题为了简化，进一步缩小到了 24 位，可以枚举。攻击的思路是，首先通过二分通关前面的猜随机数环节，然后枚举随机数生成器的内部状态，找到吻合的 seed，进而推算后续生成的随机数，求出 Flag。

首先是通过二分进行猜随机数，只需要猜几次即可：

```python
# pip3 install pwntools tqdm
from pwn import *
import ctypes
import tqdm

p = process(["./main"])

context(log_level="DEBUG")

numbers = []
for i in range(10):
    p.recvuntil(b"action:")
    p.sendline(b"1")
    left = 0
    right = 65536 - 1
    number = None
    while left < right:
        middle = (left + right) // 2
        p.recvuntil(b"guess:")
        p.sendline(str(middle).encode())
        resp = p.recvline().strip()
        if resp == b"Bigger":
            right = middle - 1
        elif resp == b"Smaller":
            left = middle + 1
        else:
            assert resp == b"You win!"
            number = middle
            break
    if number is None:
        p.recvuntil(b"guess:")
        p.sendline(str(left).encode())
        resp = p.recvline().strip()
        assert resp == b"You win!"
        number = left
    numbers.append(number)
```

接下来，就可以枚举 seed 进行攻击，这里使用 ctypes 来调用 glibc：

```python
# bruteforce random seed
libc = ctypes.CDLL("libc.so.6")
for seed in tqdm.trange(256**3):
    libc.srand(seed)
    good = True
    for i in range(len(numbers)):
        if libc.rand() % 65536 != numbers[i]:
            good = False
            break
    if good:
        print("Found seed", seed)
        break
```

最终，根据恢复出来的随机数得到 Flag，完整的攻击脚本如下：

```python
# pip3 install pwntools tqdm
from pwn import *
import ctypes
import tqdm

p = process(["./main"])

context(log_level="DEBUG")

numbers = []
for i in range(10):
    p.recvuntil(b"action:")
    p.sendline(b"1")
    left = 0
    right = 65536 - 1
    number = None
    while left < right:
        middle = (left + right) // 2
        p.recvuntil(b"guess:")
        p.sendline(str(middle).encode())
        resp = p.recvline().strip()
        if resp == b"Bigger":
            right = middle - 1
        elif resp == b"Smaller":
            left = middle + 1
        else:
            assert resp == b"You win!"
            number = middle
            break
    if number is None:
        p.recvuntil(b"guess:")
        p.sendline(str(left).encode())
        resp = p.recvline().strip()
        assert resp == b"You win!"
        number = left
    numbers.append(number)

# bruteforce random seed
libc = ctypes.CDLL("libc.so.6")
for seed in tqdm.trange(256**3):
    libc.srand(seed)
    good = True
    for i in range(len(numbers)):
        if libc.rand() % 65536 != numbers[i]:
            good = False
            break
    if good:
        print("Found seed", seed)
        break


p.recvuntil(b"action:")
p.sendline(b"2")
p.recvline()
encoded = p.recvline().decode()

# recover flag
libc.srand(seed)
for i in range(len(numbers)):
    libc.rand()

flag = bytes([a ^ (libc.rand() % 256) for a in bytes.fromhex(encoded)])
print(flag)
```

可见，如果随机数生成器的状态空间足够小，无论它计算过程多么复杂，都可以通过枚举状态空间来攻击。
