# Easy Random 5 Writeup

## 题目分析

题目附件是一个 Python 脚本，使用 Lua 5.4 的随机数生成器生成 1000 个随机数，并用这些随机数对 flag 进行异或加密：

```python
import os
import subprocess
import tempfile

flag = os.getenv("GZCTF_FLAG") or "flag{fake_flag_for_testing}"
flag = flag.encode()
code = """
for i=1,1000 do print(math.random(0)) end
"""
with tempfile.NamedTemporaryFile("w", suffix=".lua") as f:
    f.write(code)
    f.flush()

    res = subprocess.check_output(["lua", f.name])
    numbers = [int(line) for line in res.decode().splitlines()]
    print(numbers[:10])
    print([flag[i] ^ (numbers[-i] & 0xFF) for i in range(len(flag))])
```

程序输出前 10 个随机数和加密后的 flag。加密方式为：`flag[i] ^ (numbers[-i] & 0xFF)`，其中 `numbers[-i]` 表示从列表末尾开始计数的第 i 个随机数。

## 随机数生成器分析

Lua 5.4 使用的是 Xoshiro256starstar 算法，其核心实现如下：

```c
// https://github.com/lua/lua/blob/4cf498210e6a60637a7abb06d32460ec21efdbdc/lmathlib.c#L631
/*
** implementation of 'xoshiro256**' algorithm on 'Rand64' values
*/
static Rand64 nextrand (Rand64 *state) {
  Rand64 res = times9(rotl(times5(state[1]), 7));
  Rand64 t = Ishl(state[1], 17);
  Ixor(&state[2], state[0]);
  Ixor(&state[3], state[1]);
  Ixor(&state[1], state[2]);
  Ixor(&state[0], state[3]);
  Ixor(&state[2], t);
  state[3] = rotl1(state[3], 45);
  return res;
}
```

该算法除了乘法操作外，其余部分都是在 GF(2) 上的线性操作。乘法是可逆的，剩下的状态转移过程可以建模为线性方程组。

## 解题思路

我们可以利用 `gf2bv` 库来求解随机数生成器的内部状态。该库能够处理 GF(2) 上的线性方程组，并支持 Xoshiro256starstar 算法。

解题步骤如下：

1. 获取程序输出的前 10 个随机数和加密后的 flag
2. 使用 `gf2bv` 建立线性方程组，求解随机数生成器的初始状态
3. 使用恢复的状态重新生成所有 1000 个随机数
4. 使用生成的随机数解密 flag

## 解题代码

```python
# pip3 install git+https://github.com/maple3142/gf2bv pwntools
from pwn import *
from gf2bv import LinearSystem
from gf2bv.crypto.xoshiro import Xoshiro256starstar

p = process(["python3", "main.py"])
numbers = eval(p.recvline().decode())
flag_enc = eval(p.recvline().decode())

# create equations
# https://github.com/maple3142/gf2bv/blob/master/examples/xoshiro.py
lin = LinearSystem([64] * 4)
xos2 = Xoshiro256starstar(lin.gens())
zeros = [xos2.step() ^ Xoshiro256starstar.untemper(o & 0xFFFFFFFFFFFFFFFF) for o in numbers]

# found solutions
for sol in lin.solve_all(zeros):
    print("Solved")

    # recreate random number generator
    xos2 = Xoshiro256starstar(sol)
    numbers_all = [xos2() for i in range(1000)]
    flag = bytes([flag_enc[i] ^ (numbers_all[-i] & 0xFF) for i in range(len(flag_enc))])
    print(flag)
```

## 总结

本题考察了对伪随机数生成器（PRNG）的攻击。通过分析 Xoshiro256starstar 算法的线性特性，我们可以将其乘法以外的状态转移过程建模为 GF(2) 上的线性方程组。利用 `gf2bv` 库求解这些方程，即可恢复随机数生成器的内部状态，从而预测所有随机数并解密 flag。
