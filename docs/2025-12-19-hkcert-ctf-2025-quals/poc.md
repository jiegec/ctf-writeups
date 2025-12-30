# POC

Attachment:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os


class PaddingOracleClass:
    def __init__(self):
        self.key = os.urandom(16)
        self.auth = os.urandom(16)
        self.nonces = set()

        self.update(nonce=os.urandom(12))
    
    def update(self, nonce: bytes):
        assert nonce not in self.nonces, "Nonce Reuse Detected"

        self.nonces.add(nonce)
        self.nonce = nonce
        self.cnt = 2
    
    def register(self, username: bytes) -> tuple[bytes, bytes]:
        assert self.cnt, "Out of Services"
        self.cnt -= 1

        aes = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
        aes.update(self.auth)
        tok, en = aes.encrypt_and_digest(pad(username, 16))
        return tok+en

    def login(self, token: bytes) -> bytes:
        assert self.cnt, "Out of Services"
        self.cnt -= 1

        aes = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
        aes.update(self.auth)
        tok, en = token[:-16], token[-16:]
        username = unpad(aes.decrypt_and_verify(tok, en), 16)
        return username


MENU = '''
========== MENU ==========
cnt = {}
nonce = {}

= [U]pdate
= [R]egister
= [L]ogin
= [Q]uit
==========================
'''

poc = PaddingOracleClass()
while True:
    print(MENU.format(poc.cnt, poc.nonce.hex()))
    try:
        inp = input('>').upper()
        if inp == "Q":
            raise Exception
        
        elif inp == "U":
            poc.update(
                nonce=bytes.fromhex(input("nonce(hex)>"))
            )

        elif inp == "R":
            username = os.urandom(8)
            token = poc.register(username=username)
            print(f"Register!\n{token.hex()}")
            print(username.hex())

        elif inp == "L":
            token = bytes.fromhex(input("token(hex)>"))
            username = poc.login(token=token)
            print(f"Login!")
            if username == b"admin":
                with open("flag", "r") as f:
                    print(f.read())
                raise Exception
            else:
                print(f"Hello, what can I help you? {username.hex()}")
    except:
        print("Bye")
        break
```

AES-GCM nonce reuse attack:

1. Register twice with same nonce (nonce reuse)
2. Recover authentication key H using polynomial solving
3. Register with new nonce
4. Compute admin ciphertext using keystream
5. Compute admin tag using H
6. Login with forged token

Vulnerability: register() can be called multiple times with same nonce.

For how AES-GCM nonce reuse attack works, see [Tampering Detection System](../2025-12-02-blackhat-mea-ctf-final-2025/tampering-detection-system.md).

Attack script written by AI:

```python
#!/usr/bin/env sage -python
"""
Simple Sage + pwntools exploit for AES-GCM nonce reuse
Run with: sage --python simple_sage_exploit_final.py
"""

import sys
import os
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long, long_to_bytes

from sage.all import GF, PolynomialRing
from pwn import *

# Create GF(2^128) field with GCM polynomial
R = PolynomialRing(GF(2), 'x')
x = R.gen()
poly = x**128 + x**7 + x**2 + x + 1
F = GF(2**128, name='a', modulus=poly)

def int_to_gf128_gcm(x_int):
    """Convert integer to GF(2^128) element with GCM bit ordering"""
    coeffs = [0]*128
    for i in range(128):
        if (x_int >> i) & 1:
            coeffs[127 - i] = 1
    return F(R(coeffs))

def gf128_to_int_gcm(elem):
    """Convert GF(2^128) element to integer with GCM bit ordering"""
    poly = elem.polynomial()
    coeffs = poly.list()
    if len(coeffs) < 128:
        coeffs += [0] * (128 - len(coeffs))
    val = 0
    for i in range(128):
        if coeffs[127 - i] == 1:
            val |= (1 << i)
    return val

def gf128_mul_gcm(a_int, b_int):
    """GF(2^128) multiplication"""
    a = int_to_gf128_gcm(a_int)
    b = int_to_gf128_gcm(b_int)
    return gf128_to_int_gcm(a * b)

def gf128_inv_gcm(a_int):
    """GF(2^128) inverse"""
    a = int_to_gf128_gcm(a_int)
    return gf128_to_int_gcm(a ** -1)

def gf128_sqrt_gcm(a_int):
    """Square root in GF(2^128): a^(2^127)"""
    a = int_to_gf128_gcm(a_int)
    return gf128_to_int_gcm(a ** (2**127))

def recover_H(plain1, tag1, plain2, tag2):
    """Recover H from two encryptions with same nonce"""
    p1_int = bytes_to_long(plain1)
    p2_int = bytes_to_long(plain2)
    t1_int = bytes_to_long(tag1)
    t2_int = bytes_to_long(tag2)
    
    Δ_int = p1_int ^ p2_int
    T_diff_int = t1_int ^ t2_int
    
    # H^2 = T_diff * Δ^{-1}
    Δ_inv = gf128_inv_gcm(Δ_int)
    H_sq = gf128_mul_gcm(T_diff_int, Δ_inv)
    
    # H = sqrt(H_sq)
    return gf128_sqrt_gcm(H_sq)

def main():
    print("=== AES-GCM Nonce Reuse Exploit ===")
    
    # Create test flag if needed
    if not os.path.exists('flag'):
        with open('flag', 'w') as f:
            f.write('flag{test_flag_sage_pwntools}')
    
    p = process(['python3', 'main.py'])
    
    try:
        # Step 1: Update with nonce 00*12
        p.recvuntil(b'>')
        p.sendline(b'U')
        p.recvuntil(b'nonce(hex)>')
        p.sendline(b'00' * 12)
        
        # Step 2: Register twice (same nonce)
        p.recvuntil(b'>')
        p.sendline(b'R')
        resp1 = p.recvuntil(b'>').decode()
        token1_hex = resp1.split('\n')[1].strip()
        username1_hex = resp1.split('\n')[2].strip()
        
        p.sendline(b'R')
        resp2 = p.recvuntil(b'>').decode()
        token2_hex = resp2.split('\n')[1].strip()
        username2_hex = resp2.split('\n')[2].strip()
        
        # Parse data
        token1 = bytes.fromhex(token1_hex)
        token2 = bytes.fromhex(token2_hex)
        ciphertext1, tag1 = token1[:16], token1[16:]
        ciphertext2, tag2 = token2[:16], token2[16:]
        
        plaintext1 = pad(bytes.fromhex(username1_hex), 16)
        plaintext2 = pad(bytes.fromhex(username2_hex), 16)
        
        # Verify nonce reuse
        if bytes(a ^ b for a, b in zip(ciphertext1, ciphertext2)) != bytes(a ^ b for a, b in zip(plaintext1, plaintext2)):
            print("ERROR: No nonce reuse")
            return False
        
        print("✓ Nonce reuse confirmed")
        
        # Step 3: Recover H
        H = recover_H(plaintext1, tag1, plaintext2, tag2)
        print(f"H: {hex(H)}")
        
        # Step 4: Update with new nonce 01*12
        p.sendline(b'U')
        p.recvuntil(b'nonce(hex)>')
        p.sendline(b'01' * 12)
        
        # Step 5: Register once more
        p.recvuntil(b'>')
        p.sendline(b'R')
        resp3 = p.recvuntil(b'>').decode()
        token3_hex = resp3.split('\n')[1].strip()
        username3_hex = resp3.split('\n')[2].strip()
        
        token3 = bytes.fromhex(token3_hex)
        ciphertext3, tag3 = token3[:16], token3[16:]
        plaintext3 = pad(bytes.fromhex(username3_hex), 16)
        
        # Step 6: Compute admin ciphertext
        keystream = bytes(a ^ b for a, b in zip(ciphertext3, plaintext3))
        admin_plain = pad(b"admin", 16)
        admin_cipher = bytes(a ^ b for a, b in zip(admin_plain, keystream))
        
        # Step 7: Compute admin tag
        Δ = bytes(a ^ b for a, b in zip(ciphertext3, admin_cipher))
        Δ_int = bytes_to_long(Δ)
        
        H_sq = gf128_mul_gcm(H, H)
        gh_diff = gf128_mul_gcm(Δ_int, H_sq)
        gh_diff_bytes = long_to_bytes(gh_diff, 16)
        
        admin_tag = bytes(a ^ b for a, b in zip(tag3, gh_diff_bytes))
        
        # Step 8: Login as admin
        p.sendline(b'L')
        p.recvuntil(b'token(hex)>')
        
        admin_token = admin_cipher + admin_tag
        p.sendline(admin_token.hex().encode())
        
        # Get flag
        resp = p.recvall(timeout=2).decode()
        
        if 'flag' in resp.lower():
            import re
            flag_match = re.search(r'flag\{[^}]+\}', resp)
            if flag_match:
                flag = flag_match.group(0)
                print(f"\n*** FLAG: {flag} ***")
                
                return True
        
        print("Login failed")
        return False
        
    finally:
        p.close()

if __name__ == "__main__":
    if main():
        print("\n✓ Exploit succeeded!")
    else:
        print("\n✗ Exploit failed")
```
