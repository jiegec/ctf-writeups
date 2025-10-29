# litt1e

附件：

```python
from secret import flag
from Crypto.Util.number import *  

def one(): 
    p, q = getPrime(512), getPrime(512)  
    print(p * q, p >> 233) 
    if int(input("p: ")) == p: return True
    else: return False 

def two():
    p, q = getPrime(512), getPrime(512)
    print("as:", [p*q] + [getRandomRange(1, p) * p + getRandomRange(1, p >> 200) for _ in range(3)])
    if int(input("p: ")) == p: return True
    else: return False 

def three(): 
    p = getPrime(512)
    alpha = getRandomRange(1, p) 
    for _ in range(5): x_i = getRandomRange(1, p); a_i = inverse(x_i + alpha, p) % (2**400); print(p, x_i, a_i) 
    if int(input("alpha: ")) == alpha: return True
    else: return False 
 
if all([chall() for chall in [one, two, three]]):
    print("All challenges completed successfully!")
    print(flag) 
```

本题要考察三个问题的求解：

1. 给定 $n$ 以及 $p$ 的 MSB，求解 $p$，可以用 Coppersmith 求解
2. 给定若干个 $p$ 的倍数加上小随机数后的结果（外加 $n$ 是 $p$ 的整数倍），求解 $p$，这是一个 [Partial Approximate Common Divisor](../misc/acd.md) 问题，可以用 Simultaneous Diophantine approximation approach (SDA) 方法求解
3. 给定若干个 $x_i$ 以及对应的 $(x_i + \alpha)^{-1}$ 的 LSB，求解 $\alpha$，这是 Modular Inverse Hidden Number Problem 的变种，把 MSB 换成了 LSB，目前还不知道如何求解

目前的求解代码：

```python
from sage.all import *
from Crypto.Util.number import getPrime, isPrime
from pwn import *
from ast import literal_eval


# Challenge one
# Given:
# n = p * q
# known = p >> shift
# Solve p
def rsa_msb_attack(n, known, shift):
    # https://latticehacks.cr.yp.to/rsa.html
    # modulo n
    R = Zmod(n)["x"]
    x = R.gens()[0]

    # find small root of equation a + x = 0 (mod p)
    # x = the missing LSB bits
    # Coppersmith attack
    f = known * (Integer(1) << shift) + x

    # small root bound: |x| < 2^shift
    # returns small roots of this polynomial modulo some factor b of N
    # where b >= N^{beta}, which is p
    # we don't know p, but it should be around sqrt(n)
    for beta in range(40, 50):
        # test beta from 0.4 to 0.5
        beta = beta / 100
        # smaller epsilon finds larger root, but takes longer time
        roots = f.small_roots(X=1 << shift, beta=beta, epsilon=0.02)
        if len(roots) >= 1:
            break

    # roots[0] is x, compute p
    # may fail in some cases
    p = int(roots[0]) + known * (2**shift)
    q = n // p
    assert p * q == n
    return p


# Given:
# known array of x_i satisfying:
# x_i = p*q_i + r_i
# where r_i < limit
# Solve p
def sda_attack(known, limit):
    # Simultaneous Diophantine approximation approach (SDA)

    # try to use different elements as x_0
    for k in range(len(known)):
        known_new = known.copy()
        known_new[0], known_new[k] = known_new[k], known_new[0]

        # create matrix
        # limit*2,  x_1,  x_2, ..., x_t
        #       0, -x_0, ...
        #       0,    0, -x_0, ...
        #       ...
        #       0,    0,       ...,   0
        size = len(known_new)
        matrix = [[0] * size for _ in range(size)]
        matrix[0][0] = limit * 2
        for i in range(len(known_new) - 1):
            matrix[0][i + 1] = known_new[i + 1]
            matrix[i + 1][i + 1] = -known_new[0]

        B = Matrix(matrix)
        reduced = B.LLL()

        # recover q_0
        assert reduced[0][0] % (limit * 2) == 0
        q_0 = reduced[0][0] // (limit * 2)
        r_0 = known_new[0] % q_0

        assert (known_new[0] - r_0) % q_0 == 0
        p = abs((known_new[0] - r_0) // q_0)

        # validate
        bad = False
        for k in known:
            if k % p >= limit:
                # bad guess
                bad = True
                break

        if bad:
            continue

        return p

    return None


context(log_level="DEBUG")
r = process(["python3", "litt1e.py"])

# one
line = r.recvline().decode()
n, known = line.split()
n, known = int(n), int(known)
p = rsa_msb_attack(n, known, 233)
r.recvuntil(b"p: ")
r.sendline(str(p).encode())

# two
r.recvuntil(b"as: ")
known = literal_eval(r.recvline().decode())
p = sda_attack(known, (2**512 >> 200))
r.recvuntil(b"p: ")
r.sendline(str(p).encode())

# three
# TODO
r.recvuntil(b"alpha:")
```
