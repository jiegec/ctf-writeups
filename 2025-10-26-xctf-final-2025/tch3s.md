# Tch3s

对提供的 binary 逆向，可以看到它做的事情是：

1. `srand(time(NULL))`，然后用 `rand() & 0xFF` 生成 16 字节的 key
2. 用 key 对 flag 进行对称加密，然后打印出来
2. 进行多次循环，每次循环重新随机 16 字节的 plaintext，进行加密和解密，然后打印经过的时间

这里的问题是，`srand` 的 seed 空间比较小，可以通过 plaintext 的规律逆向找出 seed，从而把 key 求出来。

攻击：

```cpp
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
// first plaintext
uint8_t seq[] = {0x72, 0x0B, 0x44, 0x55, 0xC9, 0x1B, 0x6A, 0x02,
0x41, 0x35, 0x34, 0x33, 0x86, 0xB6, 0x67, 0x9D};

int main() {
  // the timestamp should be recent
  for (int seed = 1730000000; seed < 1770000000; seed++) {
    if (seed % 1000000 == 0) {
      printf("%d\n", seed);
    }
    srand(seed);
    bool good = true;
    // skip key generation
    for (int i = 0; i < 16; i++)
      rand();
    for (int i = 0; i < sizeof(seq) / sizeof(seq[0]); i++) {
      unsigned int temp = (unsigned int)rand() % 256;
      if (temp != seq[i]) {
        good = false;
        break;
      }
    }
    if (good) {
      printf("Found seed: %d\n", seed);
      break;
    }
  }
  return 0;
}
```

从而找到随机数种子 `1753843495`，意味着出题人是在 `2025年7月30日星期三上午10点44分 GMT+08:00` 的时候生成文件的（使用 <https://www.epochconverter.com/>）。接着，写一个动态库来劫持 `srand` 调用：

```c
#include <dlfcn.h>
#include <stdio.h>

extern char *getenv(char *);
typedef void (*srand_t)(int seed);
srand_t real_srand;

void srand(int seed) {
  fprintf(stderr, "called srand(%d)\n", seed);
  if (!real_srand) {
    real_srand = dlsym(RTLD_NEXT, "srand");
  }
  char *s = getenv("SRAND");
  int real_seed = 0;
  sscanf(s, "%d", &real_seed);

  fprintf(stderr, "real seed is(%d)\n", real_seed);
  real_srand(real_seed);
}
```

此时 `SRAND=1753843495 LD_PRELOAD=$PWD/hack.so ./Tch3s` 就可以得到相同的每轮 Test 的 plaintext 了。说明此时内存中已经有正确的 key。为了在不重新实现加解密算法的前提下解密，采用了调试器 `SRAND=1753843495 LD_PRELOAD=$PWD/hack.so pwndbg Tch3s` 的方法：

1. 对加密函数打断点：`b *0x5555555570ba`
2. 在加密函数的入口，`$rdi` 是明文，`$rsi` 会写入加密后的密文，`$rdx` 是 key
3. 此时修改内存，把 `$rdi` 的内容改成 `output` 文件中，加密后的 FLAG 的密文：

```
set *((int *)$rdi) = 0x60eb89b7
set *((int *)$rdi+1) = 0x88d0917a
set *((int *)$rdi+2) = 0xc4c4e288
set *((int *)$rdi+3) = 0x3f57d9e4
```

4. 然后直接调用解密函数，再打印 `$rsi`，此时解密后的结果就会显示出来：

```
p ((void (*)(void*,void*,void*))0x5555555571a1)($rdi,$rsi,$rdx)
x/s $rsi
```

5. 对 `output` 中两块密文分别进行上面的解密：

```
b *0x5555555570ba
run
set *((int *)$rdi) = 0x60eb89b7
set *((int *)$rdi+1) = 0x88d0917a
set *((int *)$rdi+2) = 0xc4c4e288
set *((int *)$rdi+3) = 0x3f57d9e4
p ((void (*)(void*,void*,void*))0x5555555571a1)($rdi,$rsi,$rdx)
x/s $rsi

run
set *((int *)$rdi) = 0x473e33f5
set *((int *)$rdi+1) = 0x910b3983
set *((int *)$rdi+2) = 0xb4d2b9ed
set *((int *)$rdi+3) = 0xc05f2afd
p ((void (*)(void*,void*,void*))0x5555555571a1)($rdi,$rsi,$rdx)
x/s $rsi
```

最终得到 Flag：`flag{tim1ng_a7t@ck_1s_dangerous}`.
