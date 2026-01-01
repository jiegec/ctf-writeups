# Day 12

Attachment:

```python
import hashlib
import fastecdsa.curve
import random
def inv_mod(k, p):
    return pow(k, p - 2, p)

# secp256k1 parameters
curve = fastecdsa.curve.secp256k1
G = curve.G
n = curve.q

def sign(msg, k, d):
    z = int.from_bytes(hashlib.sha256(msg).digest(), 'big')
    R = G * k
    r = R.x % n
    s = (inv_mod(k, n) * (z + r * d)) % n
    return r, s

def verify(msg, signature, Q):
    r, s = signature
    if not (1 <= r < n and 1 <= s < n):
        return False
    z = int.from_bytes(hashlib.sha256(msg).digest(), 'big')
    w = inv_mod(s, n)
    u1 = (z * w) % n
    u2 = (r * w) % n
    R = G * u1 + Q * u2
    return R.x % n == r

key = open('flag.txt', 'rb').read()
d = int.from_bytes(key, 'big')
d = (d % (n - 1)) + 1 
P = G * d
k = random.randint(0, n - 1)

msgs = [
    b'Beware the Krampus Syndicate!',
    b'Santa is watching...',
    b'Good luck getting the key'
]
    
for m in msgs:
    r, s = sign(m, k, d)
    r_bytes = r.to_bytes(32, 'big')
    s_bytes = s.to_bytes(32, 'big')
    print(f'msg: {m}')
    print(f'r  : {r_bytes.hex()}')
    print(f's  : {s_bytes.hex()}')
    assert verify(m, (r, s), P)
    # gonna change nonces!
    k += 1
```

```
msg: b'Beware the Krampus Syndicate!'
r  : a4312e31e6803220d694d1040391e8b7cc25a9b2592245fb586ce90a2b010b63
s  : e54321716f79543591ab4c67e989af3af301e62b3b70354b04e429d57f85aa2e
msg: b'Santa is watching...'
r  : 6c5f7047d21df064b3294de7d117dd1f7ccf5af872d053f12bddd4c6eb9f6192
s  : 1ccf403d4a520bc3822c300516da8b29be93423ab544fb8dbff24ca0e1368367
msg: b'Good luck getting the key'
r  : 2c15aceb49e63e4a2c8357102fbd345ac2cbd1b214c77fba0cd9ffe8d20d2c1e
s  : 1ee49ef3857ad1d9ff3109bfb4a91cb464ab6fdc88ace610ead7e6dee0957d95
```

Idea: ECDSA nonce reuse, we can solve k and d using the three messages.

Attack script written by AI agent with bug fixed by human:

```python
import hashlib

# secp256k1 parameters
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def inv_mod(k, p):
    return pow(k, p - 2, p)

# Parse the output data
msgs = [
    b'Beware the Krampus Syndicate!',
    b'Santa is watching...',
    b'Good luck getting the key'
]

rs_values = [
    (0xa4312e31e6803220d694d1040391e8b7cc25a9b2592245fb586ce90a2b010b63,
     0xe54321716f79543591ab4c67e989af3af301e62b3b70354b04e429d57f85aa2e),
    (0x6c5f7047d21df064b3294de7d117dd1f7ccf5af872d053f12bddd4c6eb9f6192,
     0x1ccf403d4a520bc3822c300516da8b29be93423ab544fb8dbff24ca0e1368367),
    (0x2c15aceb49e63e4a2c8357102fbd345ac2cbd1b214c77fba0cd9ffe8d20d2c1e,
     0x1ee49ef3857ad1d9ff3109bfb4a91cb464ab6fdc88ace610ead7e6dee0957d95)
]

print("Computing z values...")
# Compute z values (hash of messages)
z_values = []
for m in msgs:
    z = int.from_bytes(hashlib.sha256(m).digest(), 'big')
    z_values.append(z)
    print(f"Message: {m}, z: {hex(z)}")

r1, s1 = rs_values[0]
r2, s2 = rs_values[1]
r3, s3 = rs_values[2]
z1, z2, z3 = z_values

print(f"\nr1: {hex(r1)}")
print(f"s1: {hex(s1)}")
print(f"r2: {hex(r2)}")
print(f"s2: {hex(s2)}")
print(f"r3: {hex(r3)}")
print(f"s3: {hex(s3)}")

# Actually, let me try a different approach
# We have:
# s1 = k^-1 * (z1 + r1*d) mod n  -> k = s1^-1 * (z1 + r1*d) mod n
# s2 = (k+1)^-1 * (z2 + r2*d) mod n -> k+1 = s2^-1 * (z2 + r2*d) mod n
# Subtract: 1 = s2^-1*(z2 + r2*d) - s1^-1*(z1 + r1*d) mod n
# Multiply by s1*s2: s1 - s2 = s1*s2^-1*(z2 + r2*d) - s2*s1^-1*(z1 + r1*d) mod n
# This is messy...

# Better: From first two equations:
# k*s1 = z1 + r1*d  (1)
# (k+1)*s2 = z2 + r2*d  (2)
# Subtract (1) from (2):
# (k+1)*s2 - k*s1 = z2 - z1 + (r2 - r1)*d
# k*(s2 - s1) + s2 = z2 - z1 + (r2 - r1)*d
# So: k*(s2 - s1) - (r2 - r1)*d = z2 - z1 - s2  (A)

# From second and third:
# (k+1)*s2 = z2 + r2*d  (2)
# (k+2)*s3 = z3 + r3*d  (3)
# Subtract (2) from (3):
# (k+2)*s3 - (k+1)*s2 = z3 - z2 + (r3 - r2)*d
# k*(s3 - s2) + 2*s3 - s2 = z3 - z2 + (r3 - r2)*d
# So: k*(s3 - s2) - (r3 - r2)*d = z3 - z2 + s2 - 2*s3  (B)

print("\nSetting up equations...")
A_coeff_k = (s2 - s1) % n
A_coeff_d = (-(r2 - r1)) % n  # = (r1 - r2) % n
A_rhs = (z2 - z1 - s2) % n

B_coeff_k = (s3 - s2) % n
B_coeff_d = (-(r3 - r2)) % n  # = (r2 - r3) % n
B_rhs = (z3 - z2 + s2 - 2*s3) % n

print(f"Equation A: {hex(A_coeff_k)}*k + {hex(A_coeff_d)}*d = {hex(A_rhs)}")
print(f"Equation B: {hex(B_coeff_k)}*k + {hex(B_coeff_d)}*d = {hex(B_rhs)}")

# Solve using linear algebra
det = (A_coeff_k * B_coeff_d - A_coeff_d * B_coeff_k) % n
print(f"\nDeterminant: {hex(det)}")

if det == 0:
    print("Cannot solve - determinant is zero")
else:
    inv_det = inv_mod(det, n)
    
    # k = det([[A_rhs, A_coeff_d], [B_rhs, B_coeff_d]]) / det
    k_num = (A_rhs * B_coeff_d - A_coeff_d * B_rhs) % n
    k = (k_num * inv_det) % n
    
    # d = det([[A_coeff_k, A_rhs], [B_coeff_k, B_rhs]]) / det
    d_num = (A_coeff_k * B_rhs - A_rhs * B_coeff_k) % n
    d = (d_num * inv_det) % n
    
    print(f"\nRecovered k: {hex(k)}")
    print(f"Recovered d: {hex(d)}")
    
    # Verify with equation (1): k*s1 = z1 + r1*d mod n
    lhs = (k * s1) % n
    rhs = (z1 + r1 * d) % n
    print(f"\nVerification:")
    print(f"k*s1 mod n: {hex(lhs)}")
    print(f"z1 + r1*d mod n: {hex(rhs)}")
    print(f"Match: {lhs == rhs}")
    
    # Verify with equation (2): (k+1)*s2 = z2 + r2*d mod n
    lhs2 = ((k + 1) * s2) % n
    rhs2 = (z2 + r2 * d) % n
    print(f"(k+1)*s2 mod n: {hex(lhs2)}")
    print(f"z2 + r2*d mod n: {hex(rhs2)}")
    print(f"Match: {lhs2 == rhs2}")
    
    # Convert d to bytes
    d = d - 1 # this line is added by human
    flag_bytes = d.to_bytes(32, 'big')
    print(f"\nFlag bytes (32 bytes): {flag_bytes}")
    print(f"Flag hex: {flag_bytes.hex()}")
    
    # Try to decode
    # Remove padding
    for i in range(32):
        if flag_bytes[i] != 0:
            candidate = flag_bytes[i:]
            try:
                text = candidate.decode('ascii')
                if text.isprintable() and len(text) > 5:
                    print(f"Possible flag (starting at byte {i}): {text}")
            except:
                pass
```

Writeup written by AI agent (there is a small bug that AI forgot to add one to the flag, which is fixed in the script above):

# Advent of CTF 2025 - Day 12: Krampus Syndicate Signing Service

## Challenge Overview

The Krampus Syndicate claims their new signing service uses "bitcoin-level encryption" with industry-standard elliptic-curve cryptography. They assert the system is mathematically sound and designed so that there's absolutely no way to recover the signing key, even if you can see every signature it produces.

They provide a transcript of signed messages (`out.txt`) and the signing script (`gen.py`). Our task is to audit their claim and recover the hidden secret (flag).

## Files Provided

1. `gen.py` - The signing script
2. `out.txt` - Transcript of signed messages

## Analysis

### The Signing Script (`gen.py`)

The script implements ECDSA (Elliptic Curve Digital Signature Algorithm) using the secp256k1 curve (the same curve used in Bitcoin):

```python
import hashlib
import fastecdsa.curve
import random

curve = fastecdsa.curve.secp256k1
G = curve.G
n = curve.q

def sign(msg, k, d):
    z = int.from_bytes(hashlib.sha256(msg).digest(), 'big')
    R = G * k
    r = R.x % n
    s = (inv_mod(k, n) * (z + r * d)) % n
    return r, s
```

Key points:
- Private key `d` is derived from `flag.txt` bytes
- Nonce `k` is randomly generated once: `k = random.randint(0, n - 1)`
- **Critical vulnerability**: After each signature, `k` is incremented: `k += 1`
- Three messages are signed with nonces `k`, `k+1`, `k+2`

### The Vulnerability: Predictable Nonces

In ECDSA, the nonce `k` must be **cryptographically random and unique** for each signature. If `k` is predictable or reused, an attacker can recover the private key.

The mathematical basis:

1. ECDSA signature: `(r, s)` where:
    - `r = (k * G).x mod n`
    - `s = k⁻¹(z + r*d) mod n`
    - `z` = hash of message
    - `d` = private key
    - `n` = curve order

2. For two signatures with nonces `k` and `k+1`:
    - `s₁ = k⁻¹(z₁ + r₁*d) mod n` → `k*s₁ = z₁ + r₁*d mod n` (1)
    - `s₂ = (k+1)⁻¹(z₂ + r₂*d) mod n` → `(k+1)*s₂ = z₂ + r₂*d mod n` (2)

3. Subtracting (1) from (2):
    - `(k+1)*s₂ - k*s₁ = (z₂ - z₁) + (r₂ - r₁)*d mod n`
    - `k*(s₂ - s₁) + s₂ = (z₂ - z₁) + (r₂ - r₁)*d mod n`

With three signatures (`k`, `k+1`, `k+2`), we have three equations and two unknowns (`k` and `d`), allowing us to solve the system.

## Solution

### Step 1: Extract Data

From `out.txt`:

```
msg: b'Beware the Krampus Syndicate!'
r  : a4312e31e6803220d694d1040391e8b7cc25a9b2592245fb586ce90a2b010b63
s  : e54321716f79543591ab4c67e989af3af301e62b3b70354b04e429d57f85aa2e

msg: b'Santa is watching...'
r  : 6c5f7047d21df064b3294de7d117dd1f7ccf5af872d053f12bddd4c6eb9f6192
s  : 1ccf403d4a520bc3822c300516da8b29be93423ab544fb8dbff24ca0e1368367

msg: b'Good luck getting the key'
r  : 2c15aceb49e63e4a2c8357102fbd345ac2cbd1b214c77fba0cd9ffe8d20d2c1e
s  : 1ee49ef3857ad1d9ff3109bfb4a91cb464ab6fdc88ace610ead7e6dee0957d95
```

Compute message hashes `z`:

- `z₁ = sha256("Beware the Krampus Syndicate!")`
- `z₂ = sha256("Santa is watching...")`
- `z₃ = sha256("Good luck getting the key")`

### Step 2: Set Up Equations

From the three signatures:

1. `k*s₁ = z₁ + r₁*d mod n`
2. `(k+1)*s₂ = z₂ + r₂*d mod n`
3. `(k+2)*s₃ = z₃ + r₃*d mod n`

Rearrange to linear equations in `k` and `d`:

From (1) and (2):

- `k*(s₂ - s₁) - (r₂ - r₁)*d = z₂ - z₁ - s₂ mod n` (Equation A)

From (2) and (3):

- `k*(s₃ - s₂) - (r₃ - r₂)*d = z₃ - z₂ + s₂ - 2*s₃ mod n` (Equation B)

### Step 3: Solve Linear System

We have:

```
A: a₁*k + b₁*d = c₁ mod n
B: a₂*k + b₂*d = c₂ mod n
```

Where:

- `a₁ = s₂ - s₁ mod n`
- `b₁ = r₁ - r₂ mod n` (since `-(r₂ - r₁) = r₁ - r₂`)
- `c₁ = z₂ - z₁ - s₂ mod n`
- `a₂ = s₃ - s₂ mod n`
- `b₂ = r₂ - r₃ mod n`
- `c₂ = z₃ - z₂ + s₂ - 2*s₃ mod n`

Solve using linear algebra modulo `n`:

- Determinant: `det = a₁*b₂ - b₁*a₂ mod n`
- `k = (c₁*b₂ - b₁*c₂) * det⁻¹ mod n`
- `d = (a₁*c₂ - c₁*a₂) * det⁻¹ mod n`

### Step 4: Implementation

```python
import hashlib

# secp256k1 parameters
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def inv_mod(k, p):
    return pow(k, p - 2, p)

# Data from out.txt
msgs = [...]
rs_values = [...]
z_values = [...]

# Extract values
r1, s1 = rs_values[0]
r2, s2 = rs_values[1]
r3, s3 = rs_values[2]
z1, z2, z3 = z_values

# Set up coefficients
a1 = (s2 - s1) % n
b1 = (r1 - r2) % n
c1 = (z2 - z1 - s2) % n

a2 = (s3 - s2) % n
b2 = (r2 - r3) % n
c2 = (z3 - z2 + s2 - 2*s3) % n

# Solve
det = (a1 * b2 - b1 * a2) % n
inv_det = inv_mod(det, n)

k = ((c1 * b2 - b1 * c2) % n) * inv_det % n
d = ((a1 * c2 - c1 * a2) % n) * inv_det % n

# Convert d to bytes (flag)
flag_bytes = d.to_bytes(32, 'big')
```

### Step 5: Recover Flag

The private key `d` contains the flag:
```
Flag bytes: b'\x00\x00csd{pr3d1ct4bl3_n0nc3_==_w34k~}'
Flag: csd{pr3d1ct4bl3_n0nc3_==_w34k~}
```

## Why This Works

The vulnerability is a classic ECDSA nonce reuse attack:

1. **Nonce predictability**: Using `k`, `k+1`, `k+2` makes the nonces predictable
2. **Linear equations**: The ECDSA equations become linear when nonces are known/related
3. **Solvable system**: With 3 equations and 2 unknowns, we can solve for the private key

In secure ECDSA implementations:

- Nonce `k` must be cryptographically random for each signature
- Never reuse or predictably generate nonces
- Use RFC 6979 for deterministic nonce generation if needed

## Flag

`csd{pr3d1ct4bl3_n0nc3_==_w34k~}`

The flag itself describes the vulnerability: "predictable nonce == weak".

## Lessons Learned

1. **Cryptographic primitives ≠ secure implementation**: Even with mathematically sound algorithms (ECDSA on secp256k1), implementation flaws can break security.
2. **Nonce management is critical**: In signature schemes, nonce generation is as important as key generation.
3. **Real-world impact**: Similar vulnerabilities have affected real systems, including Bitcoin wallets with poor random number generation.
4. **Defense in depth**: Use deterministic nonce generation (RFC 6979) or hardware random number generators for critical applications.
