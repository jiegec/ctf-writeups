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
3. 给定若干个 $x_i$ 以及对应的 $(x_i + \alpha)^{-1}$ 的 LSB，求解 $\alpha$，这是 Modular Inverse Hidden Number Problem 的变种，把 MSB 换成了 LSB，解法就是把 [Modular Inverse Hidden Number Problem](../misc/mihnp.md) 里的公式，把 MSB 改成 LSB，把要找到的比较小的 LSB 部分改成 MSB 部分，只需要调整系数即可，推导过程见下面的代码

求解代码：

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

def mihnp_lsb_attack(p, k, x, b):
    # https://www.iacr.org/archive/asiacrypt2001/22480036.pdf
    # b_i = LSB_k((alpha + x_i)^{-1} \bmod p)
    # e_i = (((alpha + x_i)^{-1} \bmod p) - b_i) / (2 ** k)
    # (b_i + (2 ** k) * e_i) * (alpha + x_i) = 1 \pmod p
    # (b_0 + (2 ** k) * e_0) * (alpha + x_0) = 1 \pmod p
    # eliminate alpha:
    # (b_0 + (2 ** k) * e_0) * (b_i + (2 ** k) * e_i) * (alpha + x_i) = b_0 + (2 ** k) * e_0 \pmod p
    # (b_0 + (2 ** k) * e_0) * (b_i + (2 ** k) * e_i) * (alpha + x_0) = b_i + (2 ** k) * e_i \pmod p
    # subtract:
    # (b_0 + (2 ** k) * e_0) * (b_i + (2 ** k) * e_i) * (x_i - x_0) = b_0 + (2 ** k) * e_0 - b_i - (2 ** k) * e_i \pmod p
    # (x_i - x_0) * (2 ** (2 * k)) * e_0 * e_i + (b_0 * x_i - b_0 * x_0 + 1) * (2 ** k) * e_i +
    #   (b_i * x_i - b_i * x_0 - 1) * (2 ** k) * e_0 + b_0 * b_i * (x_1 - x_0) + b_i - b_0 = 0 \pmod p
    # e_i are small: less than p >> k
    # A_i = (x_i - x_0) * (2 ** (2 * k))
    # B_i = (b_0 * x_i - b_0 * x_0 + 1) * (2 ** k)
    # C_i = (b_i * x_i - b_i * x_0 - 1) * (2 ** k)
    # D_i = b_0 * b_i * (x_i - x_0) + b_i - b_0
    # then
    # A_i * e_0 * e_i + B_i * e_i + C_i * e_0 + D_i = 0 \pmod p

    # compute A_i, B_i, C_i, and D_i
    n = len(x) - 1
    assert len(x) == len(b)
    A = []
    B = []
    C = []
    D = []
    for i in range(1, n + 1):
        A.append((x[i] - x[0]) * (2 ** (2 * k)))
        B.append((b[0] * x[i] - b[0] * x[0] + 1) * (2**k))
        C.append((b[i] * x[i] - b[i] * x[0] - 1) * (2**k))
        D.append(b[0] * b[i] * (x[i] - x[0]) + b[i] - b[0])

    # bound for e_i
    bound = p >> k

    # construct lattice
    M = [[0] * (3 * n + 2) for _ in range(3 * n + 2)]
    # row corresponds to 1
    M[0][0] = 1
    # D_1 to D_n
    for i in range(n):
        M[0][2 * n + 2 + i] = D[i]

    # rows correspond to e_i
    for i in range(n + 1):
        M[i + 1][i + 1] = Rational(1) / bound
        if i == 0:
            # C_1 to C_n for e_0
            for j in range(n):
                M[i + 1][2 * n + 2 + j] = C[j]
        else:
            # B_1 to B_n
            M[i + 1][2 * n + 2 + i - 1] = B[i - 1]

    # rows correspond to e_0 * e_i
    for i in range(n):
        M[n + 2 + i][n + 2 + i] = Rational(1) / bound / bound
        # A_1 to A_n
        M[n + 2 + i][2 * n + 2 + i] = A[i]

    # rows for the p term
    for i in range(n):
        M[2 * n + 2 + i][2 * n + 2 + i] = p

    M = Matrix(M)
    reduced = M.LLL()

    # find a row that satisfy:
    # v = (1, e_0 / bound, \cdots, e_n / bound, e_0 * e_1 / bound, \cdots, e_0 * e_n / bound, 0, \cdots, 0)
    for i in range(3 * n + 2):
        v = reduced[i]
        if (v[0] == 1 or v[0] == -1) and all(
            v[j] == 0 for j in range(2 * n + 2, 3 * n + 2)
        ):
            e_0 = v[0] * v[1] * bound
            # (b_0 + (2 ** k) * e_0) * (alpha + x_0) = 1 \pmod p
            alpha = (pow(int(b[0] + (2**k) * e_0), -1, p) - x[0]) % p
            # the answer may be incorrect...
            return alpha
    print("Failed to find answer in the following reduction result:")
    print(reduced)
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
x = []
b = []
for i in range(5):
    p, x_i, b_i = r.recvline().decode().split()
    p, x_i, b_i = int(p), int(x_i), int(b_i)
    x.append(x_i)
    b.append(b_i)
alpha = mihnp_lsb_attack(p, 400, x, b)
r.recvuntil(b"alpha:")
r.sendline(str(alpha).encode())

r.recvall()
```
