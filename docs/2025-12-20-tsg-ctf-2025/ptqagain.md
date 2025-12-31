# PtQagain

Attachment:

```python
from secret import p, q
import os
from Crypto.Util.number import bytes_to_long, isPrime

assert isPrime(p) and p.bit_length() <= 512
assert isPrime(q) and q.bit_length() <= 512

with open('flag.txt', 'rb') as f:
    FLAG = f.read()

N = p * q

e1 = 65537
e2 = 65583

m = bytes_to_long(FLAG)
c = pow(m, e1, N)

c1 = pow(p + q, e2, N)

p = str(p)
q = str(q)
c2 = pow(int(p + q), e2, N)

print(f'{N = }')
print(f'{e1 = }')
print(f'{e2 = }')
print(f'{c = }')
print(f'{c1 = }')
print(f'{c2 = }')
```

```
N = 8415991046378822808678417368330656853369287762382257778863000234996179456832593823172163438175141897794450973258850755059008064965170892039119019048620633841637561375984016774249397631671121650489315360389403325290330278785155612107593553850666774120554971030956010302235061389242836031692105637093
e1 = 65537
e2 = 65583
c = 5574165375242524333573826610902926393700854735994229967966464169834696611810072076594787795367537651736635669504446868847168099681864093409935801174468222766808668365620150398151512438201199626223130807413078543403236814636420490358773639850910401283271784777683577389622203357416804633487506912900
c1 = 3733372451275945143106630642525005607134287402204217261131967501254130116356869822445109935329406396349828170813887809941457012269457680164427423918812605964033393533444248389803553681873885855742856069057392986629579993551342614294600091763375588208870704928674561853194758243753269168083341300444
c2 = 3733372451275945143106630642525005607134287402204217261131967501254130116356869822445109935329406396349828170813887809941457012269457680164427423918812605964033393533444248389803553681873885855742856069057392986629579993551342614294600091763375588208870704928674561853194758243753269168083341300444
```

Solved by AI:

# TSG CTF 2025 - PtQagain Writeup

**Challenge**: PtQagain  
**Category**: Crypto  
**Difficulty**: Medium  
**Author**: TSG  
**Flag**: `TSGCTF{p+q_4nd_p+q_b3in9_th3_s4me_1s_0bv1ous_ri9h7?aZ3mQ9Lk7P2xB8R}`

## Challenge Description

> I'll give you p + q encrypted twice with the same scheme! It's the same thing anyway, so no problem... right?

We're given a Python script `problem.py` and its output `output.txt`. The script encrypts a flag using RSA and also provides some additional encrypted values that leak information about the primes.

## Files Provided

- `problem.py` - The encryption script
- `output.txt` - The output containing public parameters and ciphertexts

### problem.py
```python
from secret import p, q
import os
from Crypto.Util.number import bytes_to_long, isPrime

assert isPrime(p) and p.bit_length() <= 512
assert isPrime(q) and q.bit_length() <= 512

with open('flag.txt', 'rb') as f:
    FLAG = f.read()

N = p * q

e1 = 65537
e2 = 65583

m = bytes_to_long(FLAG)
c = pow(m, e1, N)

c1 = pow(p + q, e2, N)

p = str(p)
q = str(q)
c2 = pow(int(p + q), e2, N)

print(f'{N = }')
print(f'{e1 = }')
print(f'{e2 = }')
print(f'{c = }')
print(f'{c1 = }')
print(f'{c2 = }')
```

### output.txt
```
N = 8415991046378822808678417368330656853369287762382257778863000234996179456832593823172163438175141897794450973258850755059008064965170892039119019048620633841637561375984016774249397631671121650489315360389403325290330278785155612107593553850666774120554971030956010302235061389242836031692105637093
e1 = 65537
e2 = 65583
c = 5574165375242524333573826610902926393700854735994229967966464169834696611810072076594787795367537651736635669504446868847168099681864093409935801174468222766808668365620150398151512438201199626223130807413078543403236814636420490358773639850910401283271784777683577389622203357416804633487506912900
c1 = 3733372451275945143106630642525005607134287402204217261131967501254130116356869822445109935329406396349828170813887809941457012269457680164427423918812605964033393533444248389803553681873885855742856069057392986629579993551342614294600091763375588208870704928674561853194758243753269168083341300444
c2 = 3733372451275945143106630642525005607134287402204217261131967501254130116356869822445109935329406396349828170813887809941457012269457680164427423918812605964033393533444248389803553681873885855742856069057392986629579993551342614294600091763375588208870704928674561853194758243753269168083341300444
```

## Initial Observations

1. **Standard RSA encryption**: The flag is encrypted with RSA using `e1 = 65537`
2. **Interesting leak**: Two additional values are encrypted with `e2 = 65583`:
    - `c1 = (p + q)^e2 mod N`
    - `c2 = (int(str(p) + str(q)))^e2 mod N`
3. **Critical observation**: `c1 = c2` in the output!

The equality `c1 = c2` is the key to solving this challenge. It means:
```
(p + q)^e2 ≡ (int(str(p) + str(q)))^e2 mod N
```

## Mathematical Analysis

Let's define:

- `x = p + q` (integer sum)
- `y = int(str(p) + str(q))` (concatenation of decimal representations)
- `len_q` = number of decimal digits in `q`

Then:
```
y = p * 10^len_q + q
```

From `c1 = c2`, we have:
```
x^e2 ≡ y^e2 mod N
```

Since `N = p * q`, we can analyze this modulo `q`:

1. `x ≡ p + q ≡ p (mod q)`
2. `y ≡ p * 10^len_q + q ≡ p * 10^len_q (mod q)`
3. Therefore: `p^e2 ≡ (p * 10^len_q)^e2 ≡ p^e2 * (10^len_q)^e2 (mod q)`
4. Assuming `p ≠ 0 (mod q)` (true since `p` and `q` are distinct primes), we can divide by `p^e2`:
   ```
   (10^len_q)^e2 ≡ 1 (mod q)
   ```
5. Which gives us:
   ```
   10^(len_q * e2) ≡ 1 (mod q)
   ```

This is the key insight: **`q` divides `10^(len_q * e2) - 1`**.

## Attack Strategy

Since we know `q` divides `10^(len_q * e2) - 1`, we can try to find `q` by computing:
```
gcd(10^(k * e2) - 1, N)
```
for reasonable values of `k` (the candidate for `len_q`).

We need to estimate `len_q`:
- `q` is ≤ 512 bits
- Number of decimal digits ≈ `bits * log10(2)` ≈ `512 * 0.3010 ≈ 154`
- But `N` is 990 bits, so `p` and `q` are roughly 495 bits each
- `495 * log10(2) ≈ 149` decimal digits

So we should search `k` in the range 140-160.

## Exploit Implementation

```python
from Crypto.Util.number import long_to_bytes, GCD

N = 8415991046378822808678417368330656853369287762382257778863000234996179456832593823172163438175141897794450973258850755059008064965170892039119019048620633841637561375984016774249397631671121650489315360389403325290330278785155612107593553850666774120554971030956010302235061389242836031692105637093
e1 = 65537
e2 = 65583
c = 5574165375242524333573826610902926393700854735994229967966464169834696611810072076594787795367537651736635669504446868847168099681864093409935801174468222766808668365620150398151512438201199626223130807413078543403236814636420490358773639850910401283271784777683577389622203357416804633487506912900

# Search for the correct digit length of q
for k in range(140, 160):
    value = pow(10, k * e2, N) - 1
    g = GCD(value, N)
    
    if g > 1 and g < N:
        q = g
        p = N // q
        
        # Decrypt the flag
        phi = (p - 1) * (q - 1)
        d = pow(e1, -1, phi)
        m = pow(c, d, N)
        flag = long_to_bytes(m)
        
        print(f"Found with k={k}: {flag}")
        break
```

## Results

The exploit finds a factor when `k = 144`:

- `q = 899718757349577828631761341730093220713822770643140264600436229195941807849819816835925771559643276518390048146301688389176642719947087961896703`
- `q` has 479 bits and 144 decimal digits
- `p = N // q` has 512 bits and 154 decimal digits

Decrypting the flag gives:
```
TSGCTF{p+q_4nd_p+q_b3in9_th3_s4me_1s_0bv1ous_ri9h7?aZ3mQ9Lk7P2xB8R}
```

## Why This Works

The challenge creator made a subtle but critical mistake: they assumed that encrypting `p+q` and the concatenation of `p` and `q` as strings would produce different ciphertexts. However, when these values are encrypted with the same exponent `e2` modulo `N`, and the resulting ciphertexts are equal, it reveals a mathematical relationship between `p`, `q`, and `N`.

The equality `c1 = c2` implies that `(p+q)^e2 ≡ (p*10^len_q + q)^e2 mod N`. When analyzed modulo `q`, this simplifies to `10^(len_q * e2) ≡ 1 mod q`, which means `q` divides `10^(len_q * e2) - 1`. Since `len_q` is the decimal digit length of `q` (which we can estimate), we can find `q` by checking `gcd(10^(k*e2) - 1, N)` for reasonable `k` values.

## Lessons Learned

1. **Never reuse encryption keys/schemes for different values**: Even if values seem different (like `p+q` vs. string concatenation), encrypting them with the same parameters can leak information.

2. **Mathematical relationships matter**: The equality of ciphertexts reveals algebraic relationships that can be exploited.

3. **Estimation is key**: Knowing approximate sizes (bit lengths, digit lengths) helps narrow down brute-force searches.

4. **Modular arithmetic is powerful**: Analyzing equations modulo the unknown factors (`p` and `q`) can simplify complex relationships.

## Flag
`TSGCTF{p+q_4nd_p+q_b3in9_th3_s4me_1s_0bv1ous_ri9h7?aZ3mQ9Lk7P2xB8R}`
