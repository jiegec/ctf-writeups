Primary Mathematics Revenge 500 points
================

题意
-------------

I have returned!

nc 202.112.51.234 10001

Note: The attachment has been updated. No logical changes.

Attachment: math_problem2.zip

解题步骤
-------------

这次的 `math_problem2.py` 和上次的略有不同：

```
import signal


def check(N):
    a = int(raw_input('a: '))
    b = int(raw_input('b: '))
    c = int(raw_input('c: '))

    if a <= 0 or b <= 0 or c <= 0:
        exit()
    t1 = a * (a + b) * (a + c) + b * (b + a) * (b + c) + c * (c + a) * (c + b)
    t2 = (a + b) * (a + c) * (b + c) * N
    if t1 == t2:
        return True
    else:
        return False


def handler(signum, frame):
    print('You are so slllllllllllllllllow!')
    exit(0)


def main():
    for N in range(4, 18, 2):
        if N == 8:
            continue
        if check(N):
            print('pass level {}'.format(N))
        else:
            print('wrong!')
            return
    print('You are so faaaaaaaaaaaaaaaaaaaaast!')
    print(flag)


if __name__ == "__main__":
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(20)
    main()
```

这次做了检查，并且添加了一点难度。看下论文，然后用 sage 实现了一下找正整数解的方法（[cubic.sage](cubic.sage)）：

```
import sys
n = Integer(sys.argv[1])
x, y = polygens(QQ, 'x,y')
E = EllipticCurve(-y**2+x^3+(4*n^2+12*n-3)*x^2+32*(n+3)*x)
P = E.gens()[0];
for i in range(0, 1000):
  pp = P * i
  x = pp[0]
  y = pp[1]
  a = 8*(n+3)-x+y
  b = 8*(n+3)-x-y
  c = 2*(-4*(n+3)-(n+2)*x)
  if a > 0 and b > 0 and c > 0:
    aa = a*a.denom()*b.denom()*c.denom()
    bb = b*a.denom()*b.denom()*c.denom()
    cc = c*a.denom()*b.denom()*c.denom()
    assert(aa/(bb+cc)+bb/(cc+aa)+cc/(aa+bb)==n)
    print aa
    print bb
    print cc
    break
```

然后把各个解导入到一个文件中，由于文件过大，就不在此列出了。最后可以得到结果 `THUCTF{3evenge_ECC_1s_1nt3r3string!?}` 。