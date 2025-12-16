# RSA Partial Factorization Writeup

## 题目分析

题目附件是一个 RSA 加密脚本，给出了模数 `n`、密文 `c`，以及素数 `p` 的高位（MSB）：

```python
try:
    from Crypto.Util.number import getPrime, bytes_to_long
except:
    from Cryptodome.Util.number import getPrime, bytes_to_long
import os

flag = os.getenv("GZCTF_FLAG") or "flag{fake_flag_for_testing}"
p = getPrime(512)
q = getPrime(512)
n = p * q
shift = 245
msb = p >> shift

print(f"{n = }")
print(f"{msb = }")

m = bytes_to_long(flag.encode())
e = 65537
c = pow(m, e, n)
print(f"{c = }")

"""
n = 115875396476311164878844415823841082350245930740649724159462505854041600357779384584606867590201120411413035622363685173256457589742586979659611488861300362133287019970031565288521931188121591696006529955353016686922392181478379060749179686147719197947169391942218136659087912749851657253128124861897041685071
msb = 163000585837295888314881725391367744404519415473103980454100723937398095645225036
c = 104425648636226597292001259237932911115107208342809231621163974971158265898985628696950498323584366182895045547922752200783547330765300848978348283927246463324879212916154416662729625318954521503935904635905660154612105895432496397360099609520406239812612326934889422747296854795726003883512669423580785040551
"""
```

已知信息：

- `n = p * q`，其中 `p` 和 `q` 都是 512 位素数
- `msb = p >> 245`，即 `p` 的高 267 位（512 - 245 = 267）
- 加密指数 `e = 65537`
- 密文 `c`

## 解题思路

本题考察的是 RSA 部分因子分解（Partial Factorization）攻击。RSA 的安全性依赖于大整数分解的困难性，但当攻击者知道其中一个素数 `p` 的部分信息时，可以利用 Coppersmith 方法恢复完整的 `p`。

### Coppersmith 方法简介

Coppersmith 方法是一种基于格基规约（Lattice Basis Reduction）的算法，用于求解模多项式的小根。其核心思想是：给定一个模数 `N` 和一个多项式 `f(x)`，如果存在一个较小的根 `x0` 满足 `f(x0) ≡ 0 (mod p)`，其中 `p` 是 `N` 的一个因子，那么可以通过 Coppersmith 方法找到这个根。

关于 Coppersmith 方法的详细讲解，可以参考我之前制作的 [Bilibili 视频](https://www.bilibili.com/video/BV1jj41167tU/)。

### 问题建模

已知 `p` 的高位 `msb`，设 `p` 的低位为 `x`，则有：

```
p = msb * 2^245 + x
```

其中 `0 ≤ x < 2^245`。

由于 `p` 整除 `n`，我们有：

```
f(x) = msb * 2^245 + x ≡ 0 (mod p)
```

这是一个模 `p` 的多项式方程，且 `x` 相对于 `p` 很小（`x < 2^245`，而 `p ≈ 2^512`）。这正是 Coppersmith 方法适用的场景。

## 方法一：使用 SageMath 的 small_roots 函数

SageMath 提供了内置的 `small_roots` 函数来实现 Coppersmith 攻击：

```python
# run with sage --python
from sage.all import Zmod, Integer
from Crypto.Util.number import long_to_bytes

# given numbers
n = 115875396476311164878844415823841082350245930740649724159462505854041600357779384584606867590201120411413035622363685173256457589742586979659611488861300362133287019970031565288521931188121591696006529955353016686922392181478379060749179686147719197947169391942218136659087912749851657253128124861897041685071
msb = 163000585837295888314881725391367744404519415473103980454100723937398095645225036
c = 104425648636226597292001259237932911115107208342809231621163974971158265898985628696950498323584366182895045547922752200783547330765300848978348283927246463324879212916154416662729625318954521503935904635905660154612105895432496397360099609520406239812612326934889422747296854795726003883512669423580785040551
e = 65537
shift = 245

# https://latticehacks.cr.yp.to/rsa.html
# modulo n
R = Zmod(n)["x"]
x = R.gens()[0]

# find small root of equation a + x = 0 (mod p)
# x = the missing LSB bits
# Coppersmith attack
f = msb * (Integer(1) << shift) + x

# small root bound: |x| < 2^shift
# returns small roots of this polynomial modulo some factor b of N
# where b >= N^{beta}, which is p
beta = 0.49
# smaller epsilon finds larger root, but takes longer time
roots = f.small_roots(X=1 << shift, beta=beta, epsilon=0.02)
if len(roots) >= 1:
    # roots[0] is x, compute p
    p = int(roots[0]) + msb * (2**shift)
    q = n // p
    assert p * q == n
    d = pow(e, -1, (p - 1) * (q - 1))
    m = pow(c, d, n)
    print(long_to_bytes(m))
```

## 方法二：使用 cuso 库

[cuso](https://github.com/keeganryan/cuso) 是一个实现了多变量 Coppersmith 方法的 Python 库，可以处理更复杂的同余方程问题：

```python
# run with sage --python
from sage.all import var
import cuso
from Crypto.Util.number import long_to_bytes

# given numbers
n = 115875396476311164878844415823841082350245930740649724159462505854041600357779384584606867590201120411413035622363685173256457589742586979659611488861300362133287019970031565288521931188121591696006529955353016686922392181478379060749179686147719197947169391942218136659087912749851657253128124861897041685071
msb = 163000585837295888314881725391367744404519415473103980454100723937398095645225036
c = 104425648636226597292001259237932911115107208342809231621163974971158265898985628696950498323584366182895045547922752200783547330765300848978348283927246463324879212916154416662729625318954521503935904635905660154612105895432496397360099609520406239812612326934889422747296854795726003883512669423580785040551
e = 65537
shift = 245

# adapted from https://github.com/keeganryan/cuso/blob/main/examples/rsa_partial_factorization.py
x = var("x")
relations = [msb * 2**shift + x]

p_len = (n.bit_length() + 1) // 2
bounds = {
    x: (0, 1 << shift),
}

roots = cuso.find_small_roots(
    relations=relations,
    bounds=bounds,
    modulus="p",
    modulus_multiple=n,
    modulus_lower_bound=1 << (p_len - 1),
    modulus_upper_bound=1 << p_len,
)

p = int(roots[0]["p"])
q = n // p
assert p * q == n
d = pow(e, -1, (p - 1) * (q - 1))
m = pow(c, d, n)
print(long_to_bytes(m))
```

## 总结

本题展示了 RSA 部分因子分解攻击的实际应用。当攻击者知道素数 `p` 的部分信息时，可以利用 Coppersmith 方法恢复完整的 `p`，从而破解 RSA 加密。这种攻击在实际中具有重要意义，提醒我们在实现 RSA 时要确保随机数的生成过程不会泄露任何部分信息。
