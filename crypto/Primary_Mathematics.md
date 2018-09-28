Primary Mathematics 500 points
================

题意
-------------

This is a primary math problem?

nc host ip

Attachment: math_problem.zip

解题步骤
-------------

打开 `math_problem.py` ：

```
a = int(raw_input('a: '))
b = int(raw_input('b: '))
c = int(raw_input('c: '))

if a == 0 or b == 0 or c == 0:
    exit()
N = 12
t1 = a * (a + b) * (a + c) + b * (b + a) * (b + c) + c * (c + a) * (c + b)
t2 = (a + b) * (a + c) * (b + c) * N
print(t1 / (t2 / N))
if t1 == t2:
    print(flag)
else:
    print 'try again'
```

这就是网上广泛流传的典型的椭圆曲线题。不过，由于出题人的疏忽，这里没有验证 `a,b,c` 为负数的情况，于是，输入 `1，-1, 1` 即可获得答案 `Flag: THUCTF{math_is_interestring!}`