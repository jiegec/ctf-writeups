# Simple ECDSA

```
I optimised ECDSA. My experiments confirm that it is still a correct signature scheme.

nc 52.59.124.14 5050 
```

The attachment provides two files:

The first is an implementation of elliptic curve:

```python
# ec.py
#!/usr/bin/env python3
def inverse(a,n):
	return pow(a,-1,n)

class EllipticCurve(object):
	def __init__(self, p, a, b, order = None):
		self.p = p
		self.a = a
		self.b = b
		self.n = order

	def __str__(self):
		return 'y^2 = x^3 + %dx + %d modulo %d' % (self.a, self.b, self.p)

	def __eq__(self, other):
		return (self.a, self.b, self.p) == (other.a, other.b, other.p)

class ECPoint(object):
	def __init__(self, curve, x, y, inf = False):
		self.x = x % curve.p
		self.y = y % curve.p
		self.curve = curve
		if inf or not self.is_on_curve():
			self.inf = True
			self.x = 0
			self.y = 0
		else:
			self.inf = False

	def is_on_curve(self):
		return self.y**2 % self.curve.p == (self.x**3 + self.curve.a*self.x + self.curve.b) % self.curve.p

	def copy(self):
		return ECPoint(self.curve, self.x, self.y)
	
	def __neg__(self):
		return ECPoint(self.curve, self.x, -self.y, self.inf)

	def __add__(self, point):
		p = self.curve.p
		if self.inf:
			return point.copy()
		if point.inf:
			return self.copy()
		if self.x == point.x and (self.y + point.y) % p == 0:
			return ECPoint(self.curve, 0, 0, True)
		if self.x == point.x:
			lamb = (3*self.x**2 + self.curve.a) * inverse(2 * self.y, p) % p
		else:
			lamb = (point.y - self.y) * inverse(point.x - self.x, p) % p
		x = (lamb**2 - self.x - point.x) % p
		y = (lamb * (self.x - x) - self.y) % p
		return ECPoint(self.curve,x,y)

	def __sub__(self, point):
		return self + (-point)

	def __str__(self):
		if self.inf: return 'Point(inf)'
		return 'Point(%d, %d)' % (self.x, self.y)

	def __mul__(self, k):
		k = int(k)
		base = self.copy()
		res = ECPoint(self.curve, 0,0,True)
		while k > 0:
			if k & 1:
				res = res + base
			base = base + base
			k >>= 1
		return res

	def __eq__(self, point):
		return (self.inf and point.inf) or (self.x == point.x and self.y == point.y)

if __name__ == '__main__':
	p = 17
	a = -1
	b = 1
	curve = EllipticCurve(p,a,b)
	P = ECPoint(curve, 1, 1)
	print(P+P)
```

Another is the challenge:

```python
#!/usr/bin/env python3
import os
import sys
import hashlib

from ec import *
def bytes_to_long(a):
	return int(a.hex(),16)

#P-256 parameters
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = -3
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
curve = EllipticCurve(p,a,b, order = n)
G = ECPoint(curve, 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

d_a = bytes_to_long(os.urandom(32))
P_a = G * d_a

def hash(msg):
	return int(hashlib.md5(msg).hexdigest(), 16)

def sign(msg : bytes, DEBUG = False):
	if type(msg) == str: msg = msg.encode()
	msg_hash = hash(msg)
	while True:
		k = bytes_to_long(os.urandom(n.bit_length() >> 3))
		R = G*k
		if R.inf: continue
		x,y = R.x, R.y
		r = x % n
		s = inverse(k, n) * (msg_hash + d_a) % n
		if r == 0 or s == 0: continue
		return r,s

def verify(r:int, s:int, msg:bytes, P_a):
	r %= n
	s %= n
	if r == 0 or s == 0: return False
	s1 = inverse(s,n)
	u = hash(msg) * s1 % n
	v = s1 % n
	R = G * u + P_a * v
	return r % n == R.x % n

def loop():
	while True:
		option = input('Choose an option:\n1 - get message/signature\n2 - get challenge to sign\n').strip()
		if option == '1':
			message = os.urandom(32)
			print(message.hex())
			signature = sign(message)
			assert(verify(*signature,message,P_a))
			print(signature)
		elif option == '2':
			challenge = os.urandom(32)
			signature = input(f'sign the following challenge {challenge.hex()}\n')
			r,s = [int(x) for x in signature.split(',')]
			if r == 0 or s == 0:
				print("nope")
			elif verify(r, s, challenge, P_a):
				print(open('flag.txt','r').read())
			else:
				print('wrong signature')
		else:
			print('Wrong input format')

if __name__ == '__main__':
	print('My public key is:')
	print(P_a)
	try:
		loop()
	except Exception as err:
		print(repr(err))
```

Compare with a proper ECDSA algorithm, there is a missing step in computing `s`:

```python
# vulnerable:
s = inverse(k, n) * (msg_hash + d_a) % n
# correct:
s = inverse(k, n) * (msg_hash + r * d_a) % n
```

So that in `verify`, `r` only appears on the left side of the equation:

```python
# r does not appear in these computations
s1 = inverse(s,n)
u = hash(msg) * s1 % n
v = s1 % n
R = G * u + P_a * v
# so we can assign r to R.x to make them equal
return r % n == R.x % n
```

We can just sign any message by computing `r` from the known values:

```python
from pwn import *
from ec import *
import hashlib

context(log_level="debug")


def bytes_to_long(a):
    return int(a.hex(), 16)


# P-256 parameters
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = -3
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
curve = EllipticCurve(p, a, b, order=n)
G = ECPoint(
    curve,
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def hash(msg):
    return int(hashlib.md5(msg).hexdigest(), 16)


#p = process(["/usr/bin/python3", "chall.py"])
p = remote(host="52.59.124.14", port=5050)
recv = p.recvuntil("option").splitlines()[1].decode()
P_ax = int(recv.split(",")[0].split("(")[1])
P_ay = int(recv.split(", ")[1][:-1])
P_a = ECPoint(curve, P_ax, P_ay)
p.sendline(b"2")
p.recvuntil(b"challenge")
p.recvline()
recv = p.recvline()
msg = bytes.fromhex(recv.split()[-1].decode())

# compute r
s = 1
s1 = inverse(s, n)
u = hash(msg) * s1 % n
v = s1 % n
R = G * u + P_a * v
r = R.x % n
p.sendline(f"{r},{s}".encode())
p.interactive()
```

Get flag: `ENO{1her3_i5_4_lack_0f_r2dund4ncy}`.
