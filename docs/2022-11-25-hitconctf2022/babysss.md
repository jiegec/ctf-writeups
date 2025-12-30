# Challenge

I implemented a toy Shamir's Secret Sharing for fun. Can you help me check is there any issues with this?

babysss-1068a45edf321eee75c9ceb3241a9941ab8bdc07.tar.gz

Author: maple3142

# Writeup

The challenge asks us to break the insecure implementation of SSS(Shamir's Secret Sharing). The core code is:

```python
def polyeval(poly, x):
    return sum([a * x**i for i, a in enumerate(poly)])


DEGREE = 128
SHARES_FOR_YOU = 8  # I am really stingy :)

poly = [rand.getrandbits(64) for _ in range(DEGREE + 1)]
shares = []
for _ in range(SHARES_FOR_YOU):
    x = rand.getrandbits(16)
    y = polyeval(poly, x)
    shares.append((x, y))
print(shares)

secret = polyeval(poly, 0x48763)
```

It generates a polynomial $f(x)=a_0+a_1x+\cdots+a_{128}x^{128}$ with integer coefficients and gives us 8 pairs of $(x_i, y_i)$ where $y_i=f(x_i)$. We need to recover the coefficients to get the secret. It can be solved via LLL algorithm.

The LLL algorithm finds a linear combination of basis that the length is very small. Thus, we can construct the following matrix:

$$
A = \begin{bmatrix}
1 & 1 & 1 & 1 & 1 & 1 & 1 & 1 \\
x_1 & x_2 & x_3 & x_4 & x_5 & x_6 & x_7 & x_8 \\
x_1^2 & x_2^2 & x_3^2 & x_4^2 & x_5^2 & x_6^2 & x_7^2 & x_8^2 \\
\vdots & \vdots & \vdots & \vdots & \vdots & \vdots & \vdots & \vdots \\
x_1^{128} & x_2^{128} & x_3^{128} & x_4^{128} & x_5^{128} & x_6^{128} & x_7^{128} & x_8^{128} \\
y_1 & y_2 & y_3 & y_4 & y_5 & y_6 & y_7 & y_8 \\
\end{bmatrix}
$$

Where each row forms a basis. Because $y_i = f(x_i)$, we can get:

$$
1 \times a_0 + x_i \times a_1 + \cdots x_i^{128} \times a_{128} + y_i \times (-1) = f(x_i) - f(x_i) = 0
$$

Thus the bases are linear dependent. We can verify the linear dependence via sage:

```python
# shares = [(x, y)]
DEGREE = 128
SHARES_FOR_YOU = 8

coefs = []
scale = 10 ** 100
for i in range(DEGREE+1):
    coefs.append([scale * shares[j][0] ** i for j in range(SHARES_FOR_YOU)])

coefs.append([scale * shares[j][1] for j in range(SHARES_FOR_YOU)])

m = Matrix(coefs)
res = m.LLL()[0]
print(res)
# => (0, 0, 0, 0, 0, 0, 0, 0)
```

Then, the next thing is to extract the polynomial coefficients. LLL tries the get the smallest basis, so we can leverage this to find the coefficients. Contruct the following matrix:

$$
B = \begin{bmatrix}
V & I \\
Y & 0
\end{bmatrix}
$$

Where $V$ refers to the Vandermonde matrix of $x_i$, and $Y=(y_1, y_2, \cdots y_8)$. The left half of matrix $B$ equals to matrix $A$. The right half is a identity matrix, which will retain the coefficients in the final basis.

However, this will not work:

```python
coefs = []
for i in range(DEGREE+1):
    coefs.append([shares[j][0] ** i for j in range(SHARES_FOR_YOU)] + [1 if i == j else 0 for j in range(DEGREE+1)])

coefs.append([shares[j][1] for j in range(SHARES_FOR_YOU)] + [0] * (DEGREE+1))

m = Matrix(coefs)
res = m.LLL()[0]
print(res)
# => (1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
```

The LLL algorithm is so smart that it finds a small basis, but we expect the first 8 numbers are zeros. Thus, we need to scale our numbers to force LLL algorithm to find the correct answer for us:

$$
C = \begin{bmatrix}
cV & I \\
cY & 0
\end{bmatrix}
$$

I set $c=10^{100}$ in my code:

```python
coefs = []
scale = 10 ** 100
for i in range(DEGREE+1):
    coefs.append([scale * shares[j][0] ** i for j in range(SHARES_FOR_YOU)] + [1 if i == j else 0 for j in range(DEGREE+1)])

coefs.append([scale * shares[j][1] for j in range(SHARES_FOR_YOU)] + [0] * (DEGREE+1))

m = Matrix(coefs)
res = -m.LLL()[0]
print(res)
# => (0, 0, 0, 0, 0, 0, 0, 0, 16876298701281144467, 4341623479214198629, ...)
```

The polynomial coeficients are known. The last part is easy:

```python
secret = polyeval(poly, 0x48763)
print(secret)
key = sha256(str(secret).encode()).digest()[:16]
cipher = AES.new(key, AES.MODE_CTR, nonce=b'\x8f\xa5z\xb4mZ\x97\xe9')
print(cipher.decrypt(
    b'G$\xf5\x9e\xa9\xb1e\xb5\x86w\xdfz\xbeP\xecJ\xb8wT<<\x84\xc5v\xb4\x02Z\xa4\xed\x8fB\x00[\xc0\x02\xf9\xc0x\x16\xf9\xa4\x02\xb8\xbb'))
# => hitcon{doing_SSS_in_integers_is_not_good_:(}
```

# Conclusion

The vulnerability is using integer arithmeic in SSS. Finite field arithmetic should be used instead, according to https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing.