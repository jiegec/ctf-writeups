# Easy Random 1 Writeup

## 题目描述

本题是一个基于 C 语言随机数生成器的挑战。程序首先生成一个 24 位的随机种子，然后允许用户进行两种操作：

1. 玩一个猜数字游戏（数字范围 0-65535）
2. 猜测 Flag（Flag 会与随机数进行异或加密后输出）

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

## 漏洞分析

攻击目标是 C 标准库（glibc）的 `rand()` 函数。该随机数生成器的弱点在于种子空间较小，而本题为了简化进一步将种子限制为 24 位（3 字节），使得暴力枚举成为可能。

## 攻击思路

1. **收集随机数样本**：通过二分法玩猜数字游戏，收集多个 `rand() % 65536` 的结果
2. **暴力枚举种子**：枚举所有可能的 24 位种子（0 到 2^24-1），找到与收集到的随机数序列匹配的种子
3. **恢复 Flag**：使用找到的种子预测后续随机数，解密加密的 Flag

## 解题步骤

### 1. 收集随机数样本

使用二分法快速猜中数字，收集 10 个随机数样本：

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

### 2. 暴力枚举种子

使用 `ctypes` 调用 glibc 的 `rand()` 函数，枚举所有可能的种子：

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

### 3. 恢复 Flag

使用找到的种子预测后续随机数，解密加密的 Flag：

```python
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

## 完整攻击脚本

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

## 总结

本题展示了当随机数生成器的状态空间足够小时，无论其计算过程多么复杂，都可以通过枚举状态空间来进行攻击。在实际的 CTF 比赛中，类似的随机数攻击经常出现，关键在于识别随机数生成器的弱点并收集足够的样本进行攻击。
