# lel

附件：

```python
#!/usr/bin/env sage

import sys, signal
from flag import flag
q, n, k = 127, 26, 14
F = GF(q)

def random_multiple(F):
    while 1:
        r = F.random_element()
        if r != 0: return r

def generate_challenge(F, k, n):
    G = random_matrix(F, k, n)
    Q = Permutations(n).random_element().to_matrix() * diagonal_matrix([random_multiple(F) for _ in range(n)])
    H = (G * Q).echelon_form()
    return G, H

print("Now start to be a challenger:")
challs = [generate_challenge(F, k, n) for _ in range(n)]
signal.alarm(10) 

for _ in range(n):
    G, H = challs[_]
    print(f"G matrix is: \n{G}")
    print(f"H matrix is: \n{H}")

    A = []
    for __ in range(k):
        ai = input().strip()
        try: A.append([int(i) for i in ai.split(',')])
        except: print("weird input.."); exit()

    B = []
    for __ in range(n):
        bi = input().strip()
        try: B.append([int(i) for i in bi.split(',')])
        except: print("weird input.."); exit()

    A, B = matrix(F, A), matrix(F, B)
    if not A.is_invertible() or not B.is_invertible():
        print("DAMN, I don't like your A,B")
        exit()

    if A * G * B != H:
        print("You lose..")
        exit()

print(flag)
```

本题的逻辑是：

1. 随机一个矩阵 G，对它乘以 Q 矩阵，其中 Q 矩阵的效果是对列进行重排（Permutations）然后每一列乘以一个系数（diagonal_matrix），再求 echelon form，根据线性代数知识，可知求 echelon form 过程就是高斯消元的过程，左乘了一个可逆矩阵
2. 给定 G 和 H，找到可逆矩阵 A 和 B，使得 `AGB = H`

让 DeepSeek 求解：

```
To solve this CTF challenge, we need to find invertible matrices \( A \) and \( B \) for each given pair of matrices \( G \) and \( H \) such that \( A \cdot G \cdot B = H \). The matrices \( G \) and \( H \) are provided over the finite field \( GF(127) \), with dimensions \( 14 \times 26 \) and \( 14 \times 26 \) respectively. The solution involves computing \( B \) such that \( G \cdot B = H \) and ensuring \( B \) is invertible by adding a component from the null space of \( G \). The matrix \( A \) is set to the identity matrix since \( G \cdot B = H \) already holds.

### Approach
1. **Compute \( B_0 \)**: The matrix \( B_0 \) is computed as \( B_0 = G^T \cdot (G \cdot G^T)^{-1} \cdot H \). This ensures that \( G \cdot B_0 = H \), and each column of \( B_0 \) lies in the row space of \( G \).
2. **Handle Null Space**: The null space of \( G \) is computed, and a basis matrix \( U \) is formed where each column is a basis vector of the null space.
3. **Ensure Invertibility of \( B \)**: A matrix \( C \) of size \( (n-k) \times n \) with full rank is constructed. The matrix \( B \) is then obtained as \( B = B_0 + U \cdot C \). This ensures that \( B \) is invertible because its columns span both the row space and null space of \( G \).
4. **Set \( A \) to Identity**: Since \( G \cdot B = H \), setting \( A \) to the identity matrix satisfies \( A \cdot G \cdot B = H \).

### Solution Code

#!/usr/bin/env sage

import sys

def find_AB(G, H):
    k = G.nrows()
    n = G.ncols()
    F = G.base_ring()
    GGT = G * G.transpose()
    GGT_inv = GGT.inverse()
    B0 = G.transpose() * GGT_inv * H

    null_space = G.right_kernel()
    U = null_space.matrix().transpose()
    d = U.ncols()
    C = matrix.identity(d).augment(matrix.zeros(d, n - d))
    U_C = U * C
    B = B0 + U_C
    A = matrix.identity(F, k)
    return A, B

def main():
    q = 127
    n = 26
    k = 14
    F = GF(q)

    first_line = sys.stdin.readline()
    if not first_line.startswith("Now start to be a challenger:"):
        print("Unexpected first line")
        return

    for _ in range(n):
        line = sys.stdin.readline()
        if not line.startswith("G matrix is:"):
            print("Expected G matrix line")
            return

        G_lines = []
        for i in range(k):
            line = sys.stdin.readline().strip()
            if line.startswith('['):
                line = line[1:]
            if line.endswith(']'):
                line = line[:-1]
            G_lines.append(line)

        G_list = []
        for line in G_lines:
            values = line.split()
            row = [int(val) for val in values]
            G_list.append(row)
        G = matrix(F, G_list)

        line = sys.stdin.readline()
        if not line.startswith("H matrix is:"):
            print("Expected H matrix line")
            return

        H_lines = []
        for i in range(k):
            line = sys.stdin.readline().strip()
            if line.startswith('['):
                line = line[1:]
            if line.endswith(']'):
                line = line[:-1]
            H_lines.append(line)

        H_list = []
        for line in H_lines:
            values = line.split()
            row = [int(val) for val in values]
            H_list.append(row)
        H = matrix(F, H_list)

        A, B = find_AB(G, H)

        for i in range(k):
            row = A[i]
            print(','.join(str(x) for x in row))
            sys.stdout.flush()

        for i in range(n):
            row = B[i]
            print(','.join(str(x) for x in row))
            sys.stdout.flush()

    flag_line = sys.stdin.readline()
    print(flag_line)

if __name__ == '__main__':
    main()

### Explanation
1. **Reading Input**: The script reads the matrices \( G \) and \( H \) from standard input for each of the 26 rounds.
2. **Computing \( A \) and \( B \)**: For each pair \( G \) and \( H \), the function `find_AB` computes matrices \( A \) and \( B \) as described.
3. **Output**: The matrices \( A \) and \( B \) are printed in the required format for each round. After all rounds, the flag is read and printed.

This approach efficiently solves the challenge by leveraging linear algebra properties over finite fields, ensuring correctness and invertibility of the required matrices. The solution is both optimal and straightforward, meeting the challenge constraints.
```

DeepSeek 的思路是：

1. 不管 A，让 A 等于单位矩阵，直接求 B 矩阵，使得 $GB=H$
2. 首先找到矩阵 $B_0=G^T(GG^T)^{-1}H$，那么 $GB_0=GG^T(GG^T)^{-1}H=H$ 成立
3. 接下来，求 $G$ 的零空间 $U$，即 $GU=0$ 其中 $0$ 代表全零的矩阵，然后把它填上 0（代码中乘以矩阵 $C$），直到成为方阵 $UC$
4. 那么 $B=B_0+UC$，满足 $GB=GB_0+GUC=H+0=H$

移植到本题的环境：

```python
#!/usr/bin/env sage

from pwn import *
import sys

def find_AB(G, H):
    k = G.nrows()
    n = G.ncols()
    F = G.base_ring()
    GGT = G * G.transpose()
    GGT_inv = GGT.inverse()
    B0 = G.transpose() * GGT_inv * H

    null_space = G.right_kernel()
    U = null_space.matrix().transpose()
    d = U.ncols()
    C = matrix.identity(d).augment(matrix(d, n - d))
    U_C = U * C
    B = B0 + U_C
    A = matrix.identity(F, k)
    return A, B

def main():
    q = 127
    n = 26
    k = 14
    F = GF(q)

    context(log_level = "DEBUG")
    #p = process(["sage", "task.sage"])
    p = remote("173.32.9.15", 11421)
    first_line = p.recvline().decode()
    if not first_line.startswith("Now start to be a challenger:"):
        print("Unexpected first line")
        return

    for _ in range(n):
        line = p.recvline().decode()
        if not line.startswith("G matrix is:"):
            print("Expected G matrix line")
            return

        G_lines = []
        for i in range(k):
            line = p.recvline().decode().strip()
            if line.startswith('['):
                line = line[1:]
            if line.endswith(']'):
                line = line[:-1]
            G_lines.append(line)

        G_list = []
        for line in G_lines:
            values = line.split()
            row = [int(val) for val in values]
            G_list.append(row)
        G = matrix(F, G_list)

        line = p.recvline().decode()
        if not line.startswith("H matrix is:"):
            print("Expected H matrix line")
            return

        H_lines = []
        for i in range(k):
            line = p.recvline().decode().strip()
            if line.startswith('['):
                line = line[1:]
            if line.endswith(']'):
                line = line[:-1]
            H_lines.append(line)

        H_list = []
        for line in H_lines:
            values = line.split()
            row = [int(val) for val in values]
            H_list.append(row)
        H = matrix(F, H_list)

        A, B = find_AB(G, H)

        for i in range(k):
            row = A[i]
            p.sendline((','.join(str(x) for x in row)).encode())

        for i in range(n):
            row = B[i]
            p.sendline((','.join(str(x) for x in row)).encode())

    flag_line = p.recvline().decode()
    print(flag_line)

if __name__ == '__main__':
    main()
```

可得 Flag。
