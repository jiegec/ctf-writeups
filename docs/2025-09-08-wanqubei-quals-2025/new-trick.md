# new_trick

```
CRYPTO

简单的数学知识
```

Attachment:

```python
from hashlib import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from secrets import flag, secret

assert secret < 2 ** 50
p = 115792089237316195423570985008687907853269984665640564039457584007913129639747
Q_components = (123456789, 987654321, 135792468, 864297531)

class Quaternion:
    def __init__(self, a, b, c, d):
        self.p = p
        self.a = a % self.p
        self.b = b % self.p
        self.c = c % self.p
        self.d = d % self.p

    def __repr__(self):
        return f"Q({self.a}, {self.b}, {self.c}, {self.d})"

    def __mul__(self, other):
        a1, b1, c1, d1 = self.a, self.b, self.c, self.d
        a2, b2, c2, d2 = other.a, other.b, other.c, other.d
        a_new = a1 * a2 - b1 * b2 - c1 * c2 - d1 * d2
        b_new = a1 * b2 + b1 * a2 + c1 * d2 - d1 * c2
        c_new = a1 * c2 - b1 * d2 + c1 * a2 + d1 * b2
        d_new = a1 * d2 + b1 * c2 - c1 * b2 + d1 * a2
        return Quaternion(a_new, b_new, c_new, d_new)

def power(base_quat, exp):
    res = Quaternion(1, 0, 0, 0)
    base = base_quat
    while exp > 0:
        if exp % 2 == 1:
            res = res * base
        base = base * base
        exp //= 2
    return res

Q = Quaternion(*Q_components)
R = power(Q,secret)

print("--- Public Parameters ---")
print(f"p = {p}")
print(f"Q = {Q}")
print(f"R = {R}")

'''
--- Public Parameters ---
p = 115792089237316195423570985008687907853269984665640564039457584007913129639747
Q = Q(123456789, 987654321, 135792468, 864297531)
R = Q(53580504271939954579696282638160058429308301927753139543147605882574336327145, 79991318245209837622945719467562796951137605212294979976479199793453962090891, 53126869889181040587037210462276116096032594677560145306269148156034757160128, 97368024230306399859522783292246509699830254294649668434604971213496467857155)
'''

key = md5(str(secret).encode()).hexdigest().encode()
cipher = AES.new(key=key,mode=AES.MODE_ECB)
print(cipher.encrypt(pad(flag,16)))

# b'(\xe4IJ\xfd4%\xcf\xad\xb4\x7fi\xae\xdbZux6-\xf4\xd72\x14BB\x1e\xdc\xb7\xb7\xd1\xad#e@\x17\x1f\x12\xc4\xe5\xa6\x10\x91\x08\xd6\x87\x82H\x9e'
```

It requires us to compute discrete logarithm of quaternion in a prime field. Since the secret is below `2*50`, we can use baby-step giant-step to solve it in `2**25` steps:

```python
from hashlib import *
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
import math
import tqdm

p = 115792089237316195423570985008687907853269984665640564039457584007913129639747
Q_components = (123456789, 987654321, 135792468, 864297531)


class Quaternion:
    def __init__(self, a, b, c, d):
        self.p = p
        self.a = a % self.p
        self.b = b % self.p
        self.c = c % self.p
        self.d = d % self.p

    def __eq__(self, value):
        return (
            self.p == value.p
            and self.a == value.a
            and self.b == value.b
            and self.c == value.c
            and self.d == value.d
        )

    def __hash__(self):
        return hash((self.p, self.a, self.b, self.c, self.d))

    def __repr__(self):
        return f"Q({self.a}, {self.b}, {self.c}, {self.d})"

    def __mul__(self, other):
        a1, b1, c1, d1 = self.a, self.b, self.c, self.d
        a2, b2, c2, d2 = other.a, other.b, other.c, other.d
        a_new = a1 * a2 - b1 * b2 - c1 * c2 - d1 * d2
        b_new = a1 * b2 + b1 * a2 + c1 * d2 - d1 * c2
        c_new = a1 * c2 - b1 * d2 + c1 * a2 + d1 * b2
        d_new = a1 * d2 + b1 * c2 - c1 * b2 + d1 * a2
        return Quaternion(a_new, b_new, c_new, d_new)

    def inv(self):
        len = (
            self.a * self.a + self.b * self.b + self.c * self.c + self.d * self.d
        ) % p
        inv = pow(len, -1, p)
        return Quaternion(
            self.a * inv,
            (self.p - self.b) * inv,
            (self.p - self.c) * inv,
            (self.p - self.d) * inv,
        )


def power(base_quat, exp):
    res = Quaternion(1, 0, 0, 0)
    base = base_quat
    while exp > 0:
        if exp % 2 == 1:
            res = res * base
        base = base * base
        exp //= 2
    return res


Q = Quaternion(*Q_components)
ans = Quaternion(
    53580504271939954579696282638160058429308301927753139543147605882574336327145,
    79991318245209837622945719467562796951137605212294979976479199793453962090891,
    53126869889181040587037210462276116096032594677560145306269148156034757160128,
    97368024230306399859522783292246509699830254294649668434604971213496467857155,
)


def bsgs(unit, base, target, order):
    """Solve x in pow(base,x)=target when x < order"""
    m = int(math.sqrt(order)) + 1

    # baby
    baby = {}
    current = unit
    for j in tqdm.tqdm(range(m)):
        baby[current] = j
        current = current * base

    # giant
    base_m = power(base, m)
    giant = base_m.inv()
    current = target
    for i in tqdm.tqdm(range(m)):
        if current in baby:
            return i * m + baby[current]
        current = current * giant
    return None


secret = bsgs(Quaternion(1, 0, 0, 0), Q, ans, 2**50)
print(secret)


encrypted = b"(\xe4IJ\xfd4%\xcf\xad\xb4\x7fi\xae\xdbZux6-\xf4\xd72\x14BB\x1e\xdc\xb7\xb7\xd1\xad#e@\x17\x1f\x12\xc4\xe5\xa6\x10\x91\x08\xd6\x87\x82H\x9e"

key = md5(str(secret).encode()).hexdigest().encode()
cipher = AES.new(key=key, mode=AES.MODE_ECB)
text = cipher.decrypt(encrypted)
print(text)
```

Output:

```shell
895942422329
b'flag{ef9b2a64b3ead115a48ee0b842dc19ed}\n\n\n\n\n\n\n\n\n\n'
```

Flag is `flag{ef9b2a64b3ead115a48ee0b842dc19ed}`.

Alternatively, use bsgs implementation from sage:

```python
from hashlib import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import math
import tqdm
from sage.groups.generic import bsgs

p = 115792089237316195423570985008687907853269984665640564039457584007913129639747
Q_components = (123456789, 987654321, 135792468, 864297531)


class Quaternion:
    def __init__(self, a, b, c, d):
        self.p = p
        self.a = a % self.p
        self.b = b % self.p
        self.c = c % self.p
        self.d = d % self.p

    def __eq__(self, value):
        return (
            self.p == value.p
            and self.a == value.a
            and self.b == value.b
            and self.c == value.c
            and self.d == value.d
        )

    def __hash__(self):
        return hash((self.p, self.a, self.b, self.c, self.d))

    def __repr__(self):
        return f"Q({self.a}, {self.b}, {self.c}, {self.d})"

    def __mul__(self, other):
        a1, b1, c1, d1 = self.a, self.b, self.c, self.d
        a2, b2, c2, d2 = other.a, other.b, other.c, other.d
        a_new = a1 * a2 - b1 * b2 - c1 * c2 - d1 * d2
        b_new = a1 * b2 + b1 * a2 + c1 * d2 - d1 * c2
        c_new = a1 * c2 - b1 * d2 + c1 * a2 + d1 * b2
        d_new = a1 * d2 + b1 * c2 - c1 * b2 + d1 * a2
        return Quaternion(a_new, b_new, c_new, d_new)

    def inv(self):
        len = (
            self.a * self.a + self.b * self.b + self.c * self.c + self.d * self.d
        ) % p
        inv = pow(len, -1, p)
        return Quaternion(
            self.a * inv,
            (self.p - self.b) * inv,
            (self.p - self.c) * inv,
            (self.p - self.d) * inv,
        )


Q = Quaternion(*Q_components)
ans = Quaternion(
    53580504271939954579696282638160058429308301927753139543147605882574336327145,
    79991318245209837622945719467562796951137605212294979976479199793453962090891,
    53126869889181040587037210462276116096032594677560145306269148156034757160128,
    97368024230306399859522783292246509699830254294649668434604971213496467857155,
)

secret = bsgs(
    Q,
    ans,
    (0, 2**50),
    operation=None,
    op=lambda a, b: a * b,
    inverse=lambda a: a.inv(),
    identity=Quaternion(1, 0, 0, 0),
)
print(secret)


encrypted = b"(\xe4IJ\xfd4%\xcf\xad\xb4\x7fi\xae\xdbZux6-\xf4\xd72\x14BB\x1e\xdc\xb7\xb7\xd1\xad#e@\x17\x1f\x12\xc4\xe5\xa6\x10\x91\x08\xd6\x87\x82H\x9e"

key = md5(str(secret).encode()).hexdigest().encode()
cipher = AES.new(key=key, mode=AES.MODE_ECB)
text = cipher.decrypt(encrypted)
print(text)
```
