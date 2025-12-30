polynomial 200 points
================

题意
-------------

Attachment: attach.zip

解题步骤
-------------

阅读 `poly.py` 关键部分：

```python
n = len(key) / 2
encrypted = ''
for c in flag:
    c = ord(c)
    for i in range(n):
        c = (ord(key[i]) * c + ord(key[i + n])) % 257
    encrypted += '%02x' % c
```

已知 `flag` 为 `THUCTF{...}` 的形式，于是可以列出一个同余方程组，进行求解（[polysolve.sage](polysolve.sage)）：

```python
R = IntegerModRing(257)
string = "THUCTF{}"
num = 6
left = []
for ch in string:
    row = [1]
    for i in range(0, num):
        row.insert(0, row[0]*ord(ch))
    left.append(row)
A = matrix(R, left)
b = matrix(R, [0xca, 0x6d, 0x11, 0x06, 0xca, 0xde, 0xb7, 0x46]).transpose()
res = A.solve_right(b)
print res
all = []
for ch in range(20, 127):
    row = [1]
    for i in range(0, num):
        row.insert(0, row[0]*ch)
    all.append(row)
all_matrix = matrix(R, all)
res2 = all_matrix*res
for ch in range(20, 127):
    print '%c: %02x' % (ch, res2[ch-20][0])
```

可以得到 `Key: HA` 和 `Flag: THUCTF{this_is_an_affine_cipher_acutally!}`.