# que

Attachment:

```python
#!/usr/bin/env python3
#
# BlackHat MEA 2025 Finals :: Que?
#
#

#------------------------------------------------------------------------------------------------------------------------------#
#   IMPORTS                                                                                                                    #
#------------------------------------------------------------------------------------------------------------------------------#
# Documentation imports
from __future__ import annotations
from typing import Tuple, List, Dict, NewType, Union

# Native imports
import os
import json
from hashlib import sha256
from secrets import randbelow

# External dependencies
# pip install pycryptodome
from Crypto.Cipher import AES  
from Crypto.Util.Padding import pad
from Crypto.Util.number import getPrime, isPrime, inverse

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{D3BUGG1NG_1S_FUN}')
if isinstance(FLAG, str):
    FLAG = FLAG.encode()

#------------------------------------------------------------------------------------------------------------------------------#
#   UTILITY FUNCTIONS                                                                                                          #
#------------------------------------------------------------------------------------------------------------------------------#
def GenerateSafePrime(nbit: int, kbit: int = 1) -> int:
    """ Generates a safe prime p such that p = 2*q + 1 for some prime q. """
    while True:
        p = getPrime(nbit)
        for k in range(1, 2 ** kbit):
            q = (p - 1) // (2 * k)
            if isPrime(q):
                return p
            
def IntegerHash(x: int) -> int:
    """ Returns an integer hash of given integer input. """
    return int.from_bytes(sha256(x.to_bytes(-(-x.bit_length() // 8), 'big')).digest(), 'big')

def RandomInteger(a: int, b: int = None) -> int:
    """ Returns a random integer between two given bounds. """
    if b is None:
        b = a
        a = 0
    assert a < b
    return a + randbelow(b - a)

def FlagCryptor(flag: bytes, secret: bytes) -> bytes:
    """ Encrypts a flag using a given secret. """
    return AES.new(sha256(secret).digest(), AES.MODE_ECB).encrypt(pad(flag, 16))

#------------------------------------------------------------------------------------------------------------------------------#
#   CHALLENGE CLASS                                                                                                            #
#------------------------------------------------------------------------------------------------------------------------------#
class Que:
    """ Que protocol. """
    def __init__(self, secbit: int, maskbit: int) -> None:
        self.sizes = {}
        self.sizes['m'] = maskbit
        self.sizes['k'] = secbit - self.sizes['m']
        self.sizes['r'] = self.sizes['k']
        self.sizes['e'] = secbit
        self.sizes['a'] = [self.sizes['e'], None]
        self.sizes['a'][1] = self.sizes['a'][0] + 1
        self.sizes['b'] = [self.sizes['k'] + self.sizes['m'] + self.sizes['a'][1], None]
        self.sizes['b'][1] = self.sizes['b'][0] + 1
        self.sizes['p'] = self.sizes['b'][1] + self.sizes['r'] + self.sizes['m'] + 1
        self.buffer = None

    def Initiate(self) -> dict:
        """ Initiates the Cue exchange."""
        assert self.buffer is None
        p = GenerateSafePrime(self.sizes['p'])
        mask = RandomInteger(2 ** self.sizes['m'])
        k = mask * RandomInteger(2 ** self.sizes['k'])
        r = mask * RandomInteger(2 ** self.sizes['r'])
        C1 = (k * inverse(r, p)) % p
        self.buffer = {
            'p' : p,
            'k' : k,
            'r' : r
        }
        return {
            'p' : p,
            'C1' : C1
        }
    
    def Receive(self, packet: dict) -> dict:
        """ Parses a Cue exchange initiation packet. """
        assert self.buffer is None
        assert {'p', 'C1'}.issubset(set(packet))
        assert packet['p'].bit_length() == self.sizes['p']
        assert 0 < packet['C1'] < packet['p']
        a = RandomInteger(2 ** self.sizes['a'][0], 2 ** self.sizes['a'][1])
        b = RandomInteger(2 ** self.sizes['b'][0], 2 ** self.sizes['b'][1])
        C2 = (packet['C1'] * a + b) % packet['p']
        self.buffer = {
            'p' : packet['p'],
            'a' : a,
            'b' : b
        }
        return {
            'C2': C2
        }
    
    def Continue(self, packet: dict) -> dict:
        """ Continues the Cue exchange with received packet. """
        assert self.buffer
        if ({'C2'}.issubset(set(packet))) and (set(self.buffer) == {'p', 'k', 'r'}):
            assert 0 < packet['C2'] < self.buffer['p']
            e = RandomInteger(2 ** self.sizes['e'])
            C3 = (packet['C2'] * self.buffer['r'] + e) % self.buffer['p']
            C1A = IntegerHash(e * self.buffer['k']) % self.buffer['p']
            self.buffer['e'] = e
            return {
                'C3' : C3,
                'C1A' : C1A
            }
        elif ({'C3', 'C1A'}.issubset(set(packet))) and (set(self.buffer) == {'p', 'a', 'b'}):
            assert 0 < packet['C3'] < self.buffer['p']
            assert 0 < packet['C1A'] < self.buffer['p']
            e = (packet['C3'] % self.buffer['b']) % self.buffer['a']
            k = (((packet['C3'] - e) % self.buffer['b']) * inverse(self.buffer['a'], self.buffer['p'])) % self.buffer['p']
            r = inverse(packet['C3'] // self.buffer['b'], self.buffer['p'])
            C1B = IntegerHash(e * k) % self.buffer['p']
            C2B = IntegerHash(e * r) % self.buffer['p']
            if packet['C1A'] == C1B:
                self.buffer = {
                    'key' : k
                }
                return {
                    'C2B' : C2B
                }
        elif ({'C2B'}.issubset(set(packet))) and (set(self.buffer) == {'p', 'k', 'r', 'e'}):
            assert 0 < packet['C2B'] < self.buffer['p']
            C2A = IntegerHash(self.buffer['e'] * inverse(self.buffer['r'], self.buffer['p'])) % self.buffer['p']
            if packet['C2B'] == C2A:
                self.buffer = {
                    'key' : k
                }
                return {}
        raise ValueError('Exchange desynchronisation detected.')

#------------------------------------------------------------------------------------------------------------------------------#
#   MAIN LOOP                                                                                                                  #
#------------------------------------------------------------------------------------------------------------------------------#
if __name__ == "__main__":

    # Challenge parameters
    bitSec = 128
    bitMsk = 24

    # Challenge setup
    HDR = """|
|    ________       _______  _____  
|   (  ____  \     /  ____ \/ ___ \ 
|   | (    \  )   (  (    \  /   ) )
|   | |     | |   |  (__   \/   / / 
|   | |     | |   |   __)      / /  
|   | |   __| |   |  (        (_(  
|   | (__(    (___)  (____/\     
|   (______________________/  (_)  
|
|"""
    print(HDR)

    print('|  [#] Generating transcript...')
    Aaron = Que(128, 24)
    Bobby = Que(128, 24)

    packetOne = Aaron.Initiate()
    packetOne['flag'] = FlagCryptor(FLAG, Aaron.buffer['k'].to_bytes(bitSec // 8, 'big')).hex()
    print('|\n|  Aaron -> Bobby: {}'.format(json.dumps(packetOne)))

    packetTwo = Bobby.Receive(packetOne)
    print('|\n|  Bobby -> Aaron: {}'.format(json.dumps(packetTwo)))
    
    print('|\n|  [~] Aaron then aborted the exchange... Did somebody cue them in on the problem with their Q-problem?\n|')
```

The flag is encrypted using `k`:

```python
packetOne['flag'] = FlagCryptor(FLAG, Aaron.buffer['k'].to_bytes(bitSec // 8, 'big')).hex()
```

`k` is computed from:

```python
p = GenerateSafePrime(self.sizes['p'])
mask = RandomInteger(2 ** self.sizes['m'])
k = mask * RandomInteger(2 ** self.sizes['k'])
r = mask * RandomInteger(2 ** self.sizes['r'])
C1 = (k * inverse(r, p)) % p
```

`p` and `C1` are known. `m` is less than `2**24` which we can bruteforce. `k` and `r` are less than `2**104`, so we can use cuso to solve.

Attack:

```python
import cuso
from sage.all import var
import json
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256
import tqdm

context(log_level="debug")

io = process(["python3", "que.py"])
io.recvuntil(b"Bobby: ")
data = json.loads(io.recvline())
p = data["p"]
C1 = data["C1"]
flag = bytes.fromhex(data["flag"])

bounds = {}
relations = []

k_rng = var("k_rng")
bounds[k_rng] = (0, 2**104)
r_rng = var("r_rng")
bounds[r_rng] = (0, 2**104)
relations.append(C1 * r_rng == k_rng)

roots = cuso.find_small_roots(
    relations=relations,
    bounds=bounds,
    modulus=p,
)
print(roots)

for root in roots:
    temp = root[k_rng]
    for m in tqdm.trange(2**24):
        k = temp * m
        secret = k.to_bytes(128 // 8, "big")
        dec = AES.new(sha256(secret).digest(), AES.MODE_ECB).decrypt(flag)
        try:
            res = unpad(dec, 16)
            if b"Flag" in res:
                print(res)
        except:
            pass
```
