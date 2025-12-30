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
