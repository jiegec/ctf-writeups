# RSA All in One WP

附件：

```python
try:
    from Crypto.Util.number import getPrime, isPrime
except:
    from Cryptodome.Util.number import getPrime, isPrime
import os
import random

def task0():
    # n is small
    p = getPrime(90)
    q = getPrime(90)
    n = p * q
    print("n", n)
    num = int(input())
    return num == p or num == q

def task1():
    # d is small
    p = getPrime(1024)
    q = getPrime(1024)
    n = p * q
    d = random.randrange(1, 2**500)

    while True:
        try:
            e = pow(d, -1, (p - 1) * (q - 1))
            break
        except:
            d = random.randrange(1, 2**500)
            continue
    print("n", n)
    print("e", e)
    num = int(input())
    return num == d

def task2():
    # solve p from n, e, d
    p = getPrime(1024)
    q = getPrime(1024)
    n = p * q
    d = random.randrange(1, 2**500)
    e = 0x10001
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    print("n", n)
    print("e", e)
    print("e", d)
    num = int(input())
    return num == p or num == q

def task3():
    # solve p from n, p-q
    p = getPrime(1024)
    q = getPrime(1024)
    n = p * q

    print("n", n)
    print("p-q", p - q)
    num = int(input())
    return num == p

def task4():
    # q is the next prime to p
    p = getPrime(1024)
    q = p + 1
    while not isPrime(q):
        q += 1
    n = p * q

    print("n", n)
    num = int(input())
    return num == p or num == q

tasks = [task0, task1, task2, task3, task4]
passed = set()

flag = os.getenv("GZCTF_FLAG") or "flag{fake_flag_for_testing}"

while True:
    print("Action: 1) play task 2) get flag")
    action = int(input())
    if action == 1:
        print("Which task?")
        task = int(input())
        if tasks[task]():
            passed.add(task)
            print("Passed task", task)
        else:
            print("Failed")
            break
    elif action == 2:
        if len(passed) >= 5:
            print(flag)
        break
```

本题考察了几个常见的 RSA 问题，对应的解法如下：

1. n 足够小的时候，直接用现成的工具求因子即可
2. d 比较小的时候，可以用 Wiener's Attack
3. 已知 n、e 和 d 时，可以用 [现成的算法](https://stackoverflow.com/questions/2921406/calculate-primes-p-and-q-from-private-exponent-d-public-exponent-e-and-the) 求解 p
4. 已知 n 和 p-q 时，由于 n=p*q，通过约分可以得到关于 p 的二次方程，用求根公式即可求解
5. 当 p 和 q 足够接近时，可以枚举它们的差值，然后用上述方法求解，直到找到合法的 p 为止

整合以上的攻击代码即可，下面是用 `sage --python attack.py` 执行的攻击代码：

```python
# run with: sage --python attack.py
from pwn import *
from sage.all import *

context(log_level = "debug")

io = process(["python3", "server.py"])


# task 0
io.recvuntil(b"get flag\n")
io.sendline(b"1")
io.recvuntil(b"Which task?\n")
io.sendline(b"0")
n = int(io.recvline().decode().split()[1])
io.sendline(str(Integer(n).factor()[0][0]).encode())

# task 1
io.recvuntil(b"get flag\n")
io.sendline(b"1")
io.recvuntil(b"Which task?\n")
io.sendline(b"1")
n = int(io.recvline().decode().split()[1])
e = int(io.recvline().decode().split()[1])

# https://cryptohack.gitbook.io/cryptobook/untitled/low-private-component-attacks/wieners-attack
def wiener(e, n):
    # Convert e/n into a continued fraction
    cf = continued_fraction(e/n)
    convergents = cf.convergents()
    for kd in convergents:
        k = kd.numerator()
        d = kd.denominator()
        # Check if k and d meet the requirements
        if k == 0 or d%2 == 0 or e*d % k != 1:
            continue
        phi = (e*d - 1)/k
        # Create the polynomial
        x = PolynomialRing(RationalField(), 'x').gen()
        f = x**2 - (n-phi+1)*x + n
        roots = f.roots()
        # Check if polynomial as two roots
        if len(roots) != 2:
            continue
        # Check if roots of the polynomial are p and q
        p,q = int(roots[0][0]), int(roots[1][0])
        if p*q == n:
            return d
    return None

io.sendline(str(wiener(Integer(e), Integer(n))).encode())

# task 2
io.recvuntil(b"get flag\n")
io.sendline(b"1")
io.recvuntil(b"Which task?\n")
io.sendline(b"2")
n = int(io.recvline().decode().split()[1])
e = int(io.recvline().decode().split()[1])
d = int(io.recvline().decode().split()[1])

# https://gist.github.com/ddddavidee/b34c2b67757a54ce75cb
from math import gcd  # for gcd function (or easily implementable to avoid import)
import random  # for random elements drawing in RecoverPrimeFactors

def failFunction():
    print("Prime factors not found")


def outputPrimes(a, n):
    p = gcd(a, n)
    q = int(n // p)
    if p > q:
        p, q = q, p
    print("Found factors p and q")
    print("p = {0}".format(str(p)))
    print("q = {0}".format(str(q)))
    return p, q


def RecoverPrimeFactors(n, e, d):
    """The following algorithm recovers the prime factor
    s of a modulus, given the public and private
    exponents.
    Function call: RecoverPrimeFactors(n, e, d)
    Input: 	n: modulus
                    e: public exponent
                    d: private exponent
    Output: (p, q): prime factors of modulus"""

    k = d * e - 1
    if k % 2 == 1:
        failFunction()
        return 0, 0
    else:
        t = 0
        r = k
        while r % 2 == 0:
            r = int(r // 2)
            t += 1
        for i in range(1, 101):
            g = random.randint(0, n)  # random g in [0, n-1]
            y = pow(g, r, n)
            if y == 1 or y == n - 1:
                continue
            else:
                for j in range(1, t):  # j \in [1, t-1]
                    x = pow(y, 2, n)
                    if x == 1:
                        p, q = outputPrimes(y - 1, n)
                        return p, q
                    elif x == n - 1:
                        continue
                    y = x
                    x = pow(y, 2, n)
                    if x == 1:
                        p, q = outputPrimes(y - 1, n)
                        return p, q


p, q = RecoverPrimeFactors(n, e, d)
io.sendline(str(p).encode())

# task 3
io.recvuntil(b"get flag\n")
io.sendline(b"1")
io.recvuntil(b"Which task?\n")
io.sendline(b"3")
n = int(io.recvline().decode().split()[1])
diff = int(io.recvline().decode().split()[1])

# n = p * (p - diff)
# p ** 2 - diff * p - n = 0
# p = (diff + sqrt(diff ** 2 + 4 * n)) / 2
p = (diff + math.isqrt(diff**2 + 4 * n)) // 2
q = n // p
assert n == p * q
io.sendline(str(p).encode())

# task 4
io.recvuntil(b"get flag\n")
io.sendline(b"1")
io.recvuntil(b"Which task?\n")
io.sendline(b"4")
n = int(io.recvline().decode().split()[1])

for diff in range(1, 1000):
    diff = -diff

    # n = p * (p - diff)
    # p ** 2 - diff * p - n = 0
    # p = (diff + sqrt(diff ** 2 + 4 * n)) / 2
    p = (diff + math.isqrt(diff**2 + 4 * n)) // 2
    q = n // p
    if n == p * q:
        io.sendline(str(p).encode())
        break

io.recvuntil(b"get flag\n")
io.sendline(b"2")
io.recvall()
```

以下是经过多轮对话（告诉他怎么用 `sage --python` 并提供一个正确的 Wiener's Attack 代码）后，DeepSeek 迭代出来的正确的攻击代码：

```
Perfect! I have successfully solved the CTF challenge. The exploit script now
works correctly and can obtain the flag from the server. Here's a summary of
what was accomplished:

CTF Challenge Analysis

The server.py contains 5 cryptographic challenges:

1. Task 0: Small RSA modulus (90-bit primes) - Solved using Sage's factor() function
2. Task 1: Wiener's attack (small private exponent d) - Solved using continued fractions approach
3. Task 2: Given n, e, d - Factor n using the factorization algorithm
4. Task 3: Given n and p-q - Solve quadratic equation to find p
5. Task 4: Consecutive primes - Search around sqrt(n) for consecutive primes

Exploit Implementation

The exploit script successfully:
- Uses pwntools to interact with the server process
- Implements all 5 cryptographic attacks using Sage's mathematical capabilities
- Handles the server protocol correctly
- Extracts the flag after completing all tasks

Key Improvements Made

1. Fixed Wiener's attack: Used Sage's continued fractions with proper Integer conversion
2. Corrected exponentiation: Changed ^ to ** for polynomial creation
3. Improved flag handling: Better parsing of server responses
4. Used Sage functions: Leveraged factor(), isqrt(), is_prime(), next_prime(), gcd()

The exploit is now working perfectly and can successfully obtain the flag from
the server. The script demonstrates various RSA vulnerabilities and their
exploitation techniques.
```

```python
#!/usr/bin/env sage --python

from pwn import *
import sys

# Import Sage functions
from sage.all import factor, isqrt, is_prime, next_prime, gcd

# Connect to the server via process
conn = process(["python", "server.py"])


def solve_task0():
    # Task 0: n is small (90-bit primes)
    # We can factor n using trial division or Sage's factor()
    conn.recvuntil(b"n ")
    n = int(conn.recvline().strip())
    print(f"Task 0 - n = {n}")

    # Factor n using Sage
    factors = factor(n)
    p = factors[0][0]
    q = factors[1][0]

    # Send one of the factors
    conn.sendline(str(p).encode())

    result = conn.recvline()
    print(f"Task 0 result: {result}")
    return b"Passed" in result


def solve_task1():
    # Task 1: d is small (Wiener's attack)
    conn.recvuntil(b"n ")
    n = int(conn.recvline().strip())
    conn.recvuntil(b"e ")
    e = int(conn.recvline().strip())
    print(f"Task 1 - n = {n}, e = {e}")

    # Improved Wiener attack implementation using Sage's continued fractions
    def wiener_attack(e, n):
        # Convert e/n into a continued fraction
        from sage.all import continued_fraction, RationalField, PolynomialRing, Integer

        # Convert to Sage integers
        e_sage = Integer(e)
        n_sage = Integer(n)

        cf = continued_fraction(e_sage / n_sage)
        convergents = cf.convergents()

        for kd in convergents:
            k = kd.numerator()
            d = kd.denominator()

            # Check if k and d meet the requirements
            if k == 0 or d % 2 == 0 or (e_sage * d) % k != 1:
                continue

            phi = (e_sage * d - 1) // k

            # Create the polynomial
            x = PolynomialRing(RationalField(), "x").gen()
            f = x**2 - (n_sage - phi + 1) * x + n_sage
            roots = f.roots()

            # Check if polynomial has two roots
            if len(roots) != 2:
                continue

            # Check if roots of the polynomial are p and q
            p, q = int(roots[0][0]), int(roots[1][0])
            if p * q == n:
                return d
        return None

    d = wiener_attack(e, n)

    if d is not None:
        conn.sendline(str(d).encode())
        result = conn.recvline()
        print(f"Task 1 result: {result}")
        return b"Passed" in result
    else:
        print("Wiener's attack failed")
        return False


def solve_task2():
    # Task 2: Given n, e, d, find p or q
    conn.recvuntil(b"n ")
    n = int(conn.recvline().strip())
    conn.recvuntil(b"e ")
    e = int(conn.recvline().strip())
    conn.recvuntil(b"e ")
    d = int(conn.recvline().strip())
    print(f"Task 2 - n = {n}, e = {e}, d = {d}")

    # We have n, e, d. We can recover p and q using:
    # k = (e*d - 1) / phi(n)
    # We can factor n using the method from:
    # https://crypto.stackexchange.com/questions/6361/is-sharing-the-modulus-for-multiple-rsa-key-pairs-secure

    k = e * d - 1

    # Find a factor using random g
    g = 2
    while True:
        t = k
        while t % 2 == 0:
            t //= 2
            x = pow(g, t, n)
            if x > 1 and gcd(x - 1, n) > 1:
                p = gcd(x - 1, n)
                if p != n and p != 1:
                    q = n // p
                    break
        g += 1
        if g > 100:
            break

    if "p" not in locals():
        # Alternative approach
        # Use the fact that ed = 1 (mod phi(n))
        # We can factor n using the algorithm from:
        # https://www.di-mgt.com.au/rsa_factorize_n.html
        kphi = e * d - 1
        t = kphi
        while t % 2 == 0:
            t //= 2

        a = 2
        while True:
            k = t
            while k < kphi:
                x = pow(a, k, n)
                if x != 1 and x != n - 1 and pow(x, 2, n) == 1:
                    p = gcd(x - 1, n)
                    q = n // p
                    break
                k *= 2
            a += 1
            if a > 100:
                break

    conn.sendline(str(p).encode())
    result = conn.recvline()
    print(f"Task 2 result: {result}")
    return b"Passed" in result


def solve_task3():
    # Task 3: Given n and p-q, find p
    conn.recvuntil(b"n ")
    n = int(conn.recvline().strip())
    conn.recvuntil(b"p-q ")
    p_minus_q = int(conn.recvline().strip())
    print(f"Task 3 - n = {n}, p-q = {p_minus_q}")

    # We have:
    # p - q = p_minus_q
    # p * q = n
    #
    # Let p = q + p_minus_q
    # Then: (q + p_minus_q) * q = n
    # => q^2 + p_minus_q * q - n = 0
    #
    # Solve quadratic: q = [-p_minus_q ± sqrt(p_minus_q^2 + 4n)] / 2

    discriminant = p_minus_q**2 + 4 * n
    sqrt_disc = isqrt(discriminant)

    if sqrt_disc**2 == discriminant:
        q = (-p_minus_q + sqrt_disc) // 2
        p = n // q

        conn.sendline(str(p).encode())
        result = conn.recvline()
        print(f"Task 3 result: {result}")
        return b"Passed" in result
    else:
        print("Failed to solve quadratic")
        return False


def solve_task4():
    # Task 4: q is the next prime after p
    conn.recvuntil(b"n ")
    n = int(conn.recvline().strip())
    print(f"Task 4 - n = {n}")

    # Since q is the next prime after p, we have p ~= q ~= sqrt(n)
    # We can search around sqrt(n) for consecutive primes

    root = isqrt(n)

    # Search for p and q such that p * q = n and q is next prime after p
    # Start from root and search both directions

    # Check if root is prime
    if is_prime(root):
        p_candidate = root
        q_candidate = next_prime(p_candidate)
        if p_candidate * q_candidate == n:
            conn.sendline(str(p_candidate).encode())
            result = conn.recvline()
            print(f"Task 4 result: {result}")
            return b"Passed" in result

    # Search around root
    for offset in range(1, 10000):
        # Check p = root - offset
        p_candidate = root - offset
        if is_prime(p_candidate):
            q_candidate = next_prime(p_candidate)
            if p_candidate * q_candidate == n:
                conn.sendline(str(p_candidate).encode())
                result = conn.recvline()
                print(f"Task 4 result: {result}")
                return b"Passed" in result

        # Check p = root + offset
        p_candidate = root + offset
        if is_prime(p_candidate):
            q_candidate = next_prime(p_candidate)
            if p_candidate * q_candidate == n:
                conn.sendline(str(p_candidate).encode())
                result = conn.recvline()
                print(f"Task 4 result: {result}")
                return b"Passed" in result

    print("Failed to find consecutive primes")
    return False


def main():
    # Solve all tasks
    tasks = [solve_task0, solve_task1, solve_task2, solve_task3, solve_task4]

    for i, task_func in enumerate(tasks):
        print(f"\n=== Solving Task {i} ===")

        # Select action 1 (play task)
        conn.sendline(b"1")
        conn.recvuntil(b"Which task?")

        # Select the current task
        conn.sendline(str(i).encode())

        # Solve the task
        success = task_func()

        if not success:
            print(f"Failed task {i}")
            break

    # Get the flag
    print("\n=== Getting Flag ===")
    conn.sendline(b"2")
    flag_line = conn.recvline().decode().strip()
    if "flag{" in flag_line:
        print(f"FLAG: {flag_line}")
    else:
        # Try to receive more data
        try:
            additional = conn.recv(timeout=1).decode().strip()
            print(f"FLAG: {additional}")
        except:
            print(f"FLAG: {flag_line}")

    conn.close()


if __name__ == "__main__":
    main()
```

本题受到了 [Hack The Boo CTF 2025 Leaking for Answers](../../2025-10-24-hack-the-boo-ctf-2025/leaking-for-answers.md) 的启发。此外还有很多类似的针对 RSA 的问题，求解方法也各式各样，可以参考 <https://github.com/RsaCtfTool/RsaCtfTool>。
