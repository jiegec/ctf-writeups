# Limeade

Co-authors: @JOHNKRAM

Attachments:

```python
#!/usr/bin/env python3
#
# BlackHat MEA 2025 Finals :: Limeade
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
import base64
from hashlib import sha256
from secrets import randbelow

# External dependencies
from Crypto.Cipher import AES   # pip install pycryptodome
from Crypto.Util.Padding import pad, unpad

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{D3BUGG1NG_1S_FUN}')
if isinstance(FLAG, str):
    FLAG = FLAG.encode()

#------------------------------------------------------------------------------------------------------------------------------#
#   UTILITY FUNCTIONS                                                                                                          #
#------------------------------------------------------------------------------------------------------------------------------#
def B64Encode(x: bytes) -> str:
    """ Encodes a bytestring into url-safe base64. """
    return base64.urlsafe_b64encode(x).decode().strip('=')

def B64Decode(x: str) -> bytes:
    """ Decodes a url-safe base64 string into bytes. """
    return base64.urlsafe_b64decode(x.encode() + b'===')

def FlagCryptor(flag: bytes, secret: bytes) -> bytes:
    """ Encrypts a flag using a given secret. """
    return AES.new(sha256(secret).digest(), AES.MODE_ECB).encrypt(pad(flag, 16))

#------------------------------------------------------------------------------------------------------------------------------#
#   CHALLENGE CLASS                                                                                                            #
#------------------------------------------------------------------------------------------------------------------------------#
class Lime:
    """ You can roll it, spin it, squeeze it, stretch it... It's a lime! """
    def __init__(self, volume: int) -> None:
        self.suco = []
        rinds = list(range(volume))
        while rinds:
            self.suco.append(rinds.pop(randbelow(len(rinds))))
            
    def Roll(self, suco: list) -> list:
        """ Rolls the lime. """
        assert len(suco) == len(self.suco)
        return [suco[i] for i in self.suco]
    
    def Spin(self, suco: list) -> list:
        """ Spins the lime. """
        assert len(suco) == len(self.suco)
        return [suco[self.suco.index(i)] for i in range(len(self.suco))]
    
    def Squeeze(self, suco: list) -> list:
        """ Squeezes the lime. """
        assert not len(suco) % (len(self.suco) - 1).bit_length()
        parts = (len(self.suco) - 1).bit_length()
        pieces = [suco[i:i + parts] for i in range(0, len(suco), parts)]
        pieces = [sum(j * 2 ** i for i,j in enumerate(k)) for k in pieces]
        pieces = [self.suco[i] for i in pieces]
        pieces = [[(j >> i) & 1 for i in range(parts)] for j in pieces]
        return [i for j in pieces for i in j]
    
    def Stretch(self, suco: list) -> list:
        """ Stretches the lime. """
        assert not len(suco) % (len(self.suco) - 1).bit_length()
        parts = (len(self.suco) - 1).bit_length()
        pieces = [suco[i:i + parts] for i in range(0, len(suco), parts)]
        pieces = [sum(j * 2 ** i for i,j in enumerate(k)) for k in pieces]
        pieces = [self.suco.index(i) for i in pieces]
        pieces = [[(j >> i) & 1 for i in range(parts)] for j in pieces]
        return [i for j in pieces for i in j]
    
class Juicer:
    """ A juicer to juice the limes... for that sweet, sweet limeade! """
    def __init__(self, limes: list, volume: int, sugars: int, iceCubes: int, secretIngredient: int) -> None:
        self.limes = limes
        self.volume = volume
        self.sugars = sugars
        self.iceCubes = iceCubes
        self.secretIngredient = secretIngredient

    def _Stir(self, one: list, two: list) -> list:
        """ Stirs the juice. """
        assert len(one) == len(two)
        return [i ^ j for i,j in zip(one, two)]

    def Pour(self, cup: bytes, tap: int) -> bytes:
        """ Pours the juice from the tap. """
        assert len(cup) * 8 <= self.volume
        cup = [int(i) for i in '{:0{n}b}'.format(int.from_bytes(cup, 'big'), n=self.volume)]
        tap = [int(i) for i in '{:0{n}b}'.format((self.secretIngredient + tap) % (2**self.volume), n=self.volume)]
        for i in range(self.sugars):
            cup = self._Stir(self.limes[3*i].Roll(tap), cup)
            for _ in range(self.iceCubes):
                cup = self.limes[3*i + 1].Squeeze(self.limes[3*i + 2].Roll(cup))
        cup = self._Stir(self.limes[3*(i + 1)].Roll(tap), cup)
        return int(''.join(str(i) for i in cup), 2).to_bytes(self.volume // 8, 'big')
    
    def Depour(self, cup: bytes, tap: int) -> bytes:
        """ Sucks the juice back up through the tap... Ehm??? """
        assert len(cup) * 8 <= self.volume
        cup = [int(i) for i in '{:0{n}b}'.format(int.from_bytes(cup, 'big'), n=self.volume)]
        tap = [int(i) for i in '{:0{n}b}'.format((self.secretIngredient + tap) % (2**self.volume), n=self.volume)]
        cup = self._Stir(self.limes[3*self.sugars].Roll(tap), cup)
        for i in range(self.sugars - 1, -1, -1):
            for _ in range(self.iceCubes):
                cup = self.limes[3*i + 2].Spin(self.limes[3*i + 1].Stretch(cup))
            cup = self._Stir(self.limes[3*i].Roll(tap), cup)
        return int(''.join(str(i) for i in cup), 2).to_bytes(self.volume // 8, 'big').lstrip(b'\x00')

#------------------------------------------------------------------------------------------------------------------------------#
#   MAIN LOOP                                                                                                                  #
#------------------------------------------------------------------------------------------------------------------------------#
if __name__ == "__main__":

    # Challenge parameters
    volume = 256
    sugars = 2
    iceCubes = 16

    # Challenge setup
    secretIngredient = randbelow(2 ** volume)
    limes = [Lime(volume) for _ in range(3 * sugars + 1)]
    juicer = Juicer(limes, volume, sugars, iceCubes, secretIngredient)

    HDR = """|
|    ___    __ ___ ___             ______
|   |   |  |__|   Y   .-----.---.-|      \ .-----.
|   |.  |  |  |.      |  -__|  _  |.  |   \|  -__|
|   |.  |__|__|. \_/  |_____|___._|.  |    |_____|
|   |:  |   | |:  |   |           |:  |    /
|   |::.. . | |::.|:. |           |::.. . /
|   `-------' `--- ---'           `------'
|
|  [~] Flag = {}
|"""
    print(HDR.format(B64Encode(FlagCryptor(FLAG, secretIngredient.to_bytes(volume // 8, 'big')))))

    print('|  [~] Look at these beautiful limes I bought this morning ~ !')
    print('|    limes = {}'.format('.'.join(B64Encode(bytes(i.suco)) for i in limes)))
    print('|    I made some limeade with them. Feel free to pour yourself some, as long as you bring your own cup and tap ~ !')

    # Main
    OPS = ['Pour', 'Depour', 'Quit']
    TUI = "|\n|  Menu:\n|    " + "\n|    ".join('[' + i[0] + ']' + i[1:] for i in OPS) + "\n|"

    while True:
        try:

            print(TUI)
            choice = input('|  > ').lower()

            # [Q]uit
            if choice == 'q':
                print("|\n|  [~] Stay safe ~ !\n|")
                break

            elif choice == 'p':
                userInput = input("|  > (B64.B64) ").split('.')
                cupFull = juicer.Pour(B64Decode(userInput[0]), int.from_bytes(B64Decode(userInput[1]), 'big'))
                print('|\n|  [~] Enjoooy ~\n|    cupFull = {}'.format(B64Encode(cupFull)))

            elif choice == 'd':
                userInput = input("|  > (B64.B64) ").split('.')
                cupEmpty = juicer.Depour(B64Decode(userInput[0]), int.from_bytes(B64Decode(userInput[1]), 'big'))
                print('|\n|  [~] Here is your cup back.\n|    cupEmpty = {}'.format(B64Encode(cupEmpty)))

            else:
                print("|\n|  [!] Invalid choice.")

        except KeyboardInterrupt:
            print("\n|\n|  [~] Tchau ~ !\n|")
            break

        except Exception as e:
            print('|\n|  [!] ERROR: {}'.format(e))
```

We are given a block cipher that contains the following operations:

1. Roll/Spin: permutation
2. Squeeze/Stretch: S-box
3. Stir: XOR

Pour is encrypt, Depour is decrypt. We need to recover the key.

@JOHNKRAM found a way to deduce each bit of the key (except bit 255):

```python
# guess key bit[i]
s = token_bytes(32)
i = 0
d = 1 << i
d0 = (1 << (limes[0].suco.index(i ^ 255) ^ 255)).to_bytes(32, 'big')
d2 = (1 << (limes[6].suco.index(i ^ 255) ^ 255)).to_bytes(32, 'big')
t = juicer.Pour(strxor(s, d0), d)
t = juicer.Depour(strxor(t, d2), 0)
t = juicer.Pour(strxor(t, d0), d)
t = juicer.Depour(strxor(t, d2), 0)
# this means key bit i == 0
print(t == s)
t = juicer.Pour(strxor(s, d0), -d)
t = juicer.Depour(strxor(t, d2), 0)
t = juicer.Pour(strxor(t, d0), -d)
t = juicer.Depour(strxor(t, d2), 0)
# this means key bit i == 1
print(t == s)
```

## Illustrated method

The idea is:

1. add one bit to the key, if it overflows into an upper bit, the original bit was one; otherwise, if no overflow occurs, the original bit was zero
2. now we try to distinguish between the two cases: we hope to identify when overflow does not happen, then we can use `key` and `key + 1` as two keys to encrypt/decrypt, where the two keys only differ in one bit
3. consider the propagation of the differential between the two keys: we want to keep the two paths as close as we can
4. consider `juicer.Pour(s, 0)` and `juicer.Pour(s, d)` where d has only one bit set to one; now we want the two encryptions to be close
5. so we compensate for the initial `self.limes[0].Roll(tap)` by using `strxor(s, d0)`; now the first round become the same for `juicer.Pour(s, 0)` and `juicer.Pour(strxor(s, d0), d)`
6. the second round will mismatch, because we cannot compensate for `self.limes[3].Roll(tap)`; but its fine, because it is reversible, we can compensate for it later
7. now we need to compensate for `self.limes[6].Roll(tap)` by going backwards: compensate for the last `self.limes[6].Roll(tap)` in `_Stir` by `strxor(t, d2)`
8. repeat the process twice, so `self.limes[3].Roll(tap)` is compensated, we can recover the original plaintext if our guess is right

Here is an example of how this works:

Entering round 1:

```
Compare Pour(s, 0) and Pour(strxor(s, d0), d):
Enter round 1
Pour(s, 0)             cup = 0110000101100001111111111010101110100110100100001010010111011001100101010101011011111001001101000101100000000011001110110011011001111100100010000100010000011110010111010111101100101101100110100010100000100110101000010100101011001101001101010110111011101101
Pour(strxor(s, d0), d) cup = 0110000101100001111111111010101110100110100100001010010111011001100101010101011011111001001101000101100000000011001110110011011001111100100010000100010000011110010111010111101100111101100110100010100000100110101000010100101011001101001101010110111011101101
Diff                   cup = 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000
```

There is only one bit different, to compensate for `juicer.limes[0].Roll(tap)`, we can see the effect:

```
After stir(xor) in round 1
Pour(s, 0)             cup = 0101001000010001110001111000000000110110100000110100001011100111101010010001001111011101111011111000011100101110100100111101000001100101010101110001000001111111001111110001000010001110011010111010010010010001111001111100010110000000001000110000000100000100
Pour(strxor(s, d0), d) cup = 0101001000010001110001111000000000110110100000110100001011100111101010010001001111011101111011111000011100101110100100111101000001100101010101110001000001111111001111110001000010001110011010111010010010010001111001111100010110000000001000110000000100000100
Diff                   cup = 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

Because `cup` is the same, so the ice cubes (s-box) remain the same:

```
After ice cubes(s-box) in round 1
Pour(s, 0)             cup = 1011100001001001110011011011110000110010011010111101010001000000000001011101100111110000001101111011111110001000000001101111000011100100001010001111000101111000100110010011011111000000000000010000000010111111001010100011101100011111111111101000010110010110
Pour(strxor(s, d0), d) cup = 1011100001001001110011011011110000110010011010111101010001000000000001011101100111110000001101111011111110001000000001101111000011100100001010001111000101111000100110010011011111000000000000010000000010111111001010100011101100011111111111101000010110010110
Diff                   cup = 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

Now for the second round, because we did not compensate for `juicer.limes[3].Roll(tap)`, now the result differs again:

```
After stir(xor) in round 2
Pour(s, 0)             cup = 0100111101101000000101010011000110101101111111101100111111010101100010110001101110110101011101101100101100111001110100001101001011011000110010001010111101000110111111000111000010100001010110100110101110001001001101100001101000000111010001011010111110100110
Pour(strxor(s, d0), d) cup = 0100111101101000000101010011000110101101111111101100111111010101100010110001101110110101011101101100101100111001110100001101001011011000110010001010111101000110111111000111000010100001010110100110101110001001001101100001101000000111010001011010111110100111
Diff                   cup = 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
```

The S-Boxes propagates the difference:

```
After ice cubes(s-box) in round 2
Pour(s, 0)             cup = 0000101000111001001100000011111110111111101000001000010100101001110000001110010100011100110110001000100110010101110011010101110110011001100110010011010110011001000101110111001010111111011111011010111001111111110001000010011100011111101111001101011110111111
Pour(strxor(s, d0), d) cup = 0000100010101111010100011000011010001111000000001001101101001100011010110100011001100010100000110010001011101111000010010001111100111010101001001111100110010010110110010010110000111010010011001011011101101110110101110100011001001001001011000110101001000001
Diff                   cup = 0000001010010110011000011011100100110000101000000001111001100101101010111010001101111110010110111010101101111010110001000100001010100011001111011100110000001011110011100101111010000101001100010001100100010001000100110110000101010110100100001011110111111110
```

After the last stir(xor), the diff may seem scary:

```
After last stir(xor)
Pour(s, 0)             cup = 1011001110110101001011100110100101001000100101101110001111111111100001001111100010010000100100110011101101001100110001101110110100111001010111001101100010001000100010010111011001111111010100000101110010100110111000010101100101110000001111111111001110101011
Pour(strxor(s, d0), d) cup = 1011000100100011010011111101000101111000001101101111110110011010001011110101101111101110110010001001000000110110000000101010111110011010011000010001010010000011010001110010100011111010011000010100010110110111111100100011100000100110101011110100111001010101
Diff                   cup = 0000001010010110011000011011100000110000101000000001111001100101101010111010001101111110010110111010101101111010110001000100001010100011001111011100110000001011110011100101111010000101001100010001100100010001000100110110000101010110100100001011110111111110
```

But don't worry: we are decrypting backwards right now: we are comparing `Depour(Pour(s, 0), 0)` and `Depour(strxor(Pour(strxor(s, d0)), d2), 0)`:

```
Compare Depour(Pour(s, 0), 0) Depour(strxor(Pour(strxor(s, d0)), d2), 0)
After first stir(xor)
Depour(Pour(s, 0), 0)                      cup = 0011111110011010000100010100111110101100010000001110011110100010001001111001110111101111001101011011100011101111010011001001111010011101000111011001000010111100101011100011111000010011110000100100010110101101011000100001100001000101001101011100100101000011
Depour(strxor(Pour(strxor(s, d0)), d2), 0) cup = 1000001110010001111111101110111010100000000000011000111101111001111011111110011100101001000100111010101010001100110101100010011110110010101100000110111111000110110010010111001000101101011000010101000101111111000011110010001100101010010010101110101000110100
Diff                                       cup = 1011110000001011111011111010000100001100010000010110100011011011110010000111101011000110001001100001001001100011100110101011100100101111101011011111111101111010011001110100110000111110101000110001010011010010011011010011101101101111011111110010001101110111
```

The diff still looks scary, but after the ice cubes (s-box) in round 2(the first round in decryption):

```
After ice cubes (s-box) in round 2
Depour(Pour(s, 0), 0)                      cup = 0001111010100111111010110101100001000010011110001010101000000111010001010000010100001111111000100111011111000111010010011110000011001000010111101001100000111010001100010000010110100110110111001110110010110000101101100111101011000111101101111100110101010011
Depour(strxor(Pour(strxor(s, d0)), d2), 0) cup = 0001111010100101111010110101100001000010011110001010101000000111010001010000010100001111111000100111011111000111010010011110000011001000010111101001100000111010001100010000010110100110110111001110110010110000101101100111101011000111101101111100110101010011
Diff                                       cup = 0000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

The diff is only one bits! This is because the cipher is reversible. However, we the S-Box in round 1(second round in decryption) propagates the diff:

```
After ice cubes (s-box) in round 1
Depour(Pour(s, 0), 0)                      cup = 0101000110101100111000111100100100110010101001010100110000011000100110010100000001101011111000100000110100010100001011110110110111111000010100100110101110111110110011001100110100010101010101010000001111111101011001110001011101101110011010011001010101000111
Depour(strxor(Pour(strxor(s, d0)), d2), 0) cup = 1111010010000110001100001111001110101001110011101011101000100010010101101000011001001001101110001010100011111100101101001001100001010101000100010011100101101010011101101101110100001000010000001111111000100101011101110100010100010010011101001010001110000011
Diff                                       cup = 1010010100101010110100110011101010011011011010111111011000111010110011111100011000100010010110101010010111101000100110111111010110101101010000110101001011010100101110100001000000011101000101011111110111011000000100000101001001111100000111010011011011000100
```

Don't worry, we can handle this: just encrypt and go forward again. By encrypt-decrypt-encrypt-decrypt, the diff eventually becomes zero.

## Attack script

Given the algorithm, we can recover each bit of the key, and bruteforce the bit 255 to recover flag:

```python
from __future__ import annotations
from typing import Tuple, List, Dict, NewType, Union
import os
import base64
from hashlib import sha256
from secrets import randbelow, token_bytes

try:
    from Cryptodome.Cipher import AES  # pip install pycryptodome
    from Cryptodome.Util.Padding import pad, unpad
    from Cryptodome.Util.strxor import strxor
except:
    from Crypto.Cipher import AES  # pip install pycryptodome
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Util.strxor import strxor
from pwn import *


def B64Encode(x: bytes) -> str:
    """Encodes a bytestring into url-safe base64."""
    return base64.urlsafe_b64encode(x).decode().strip("=")


def B64Decode(x: str) -> bytes:
    """Decodes a url-safe base64 string into bytes."""
    return base64.urlsafe_b64decode(x.encode() + b"===")


class Lime:
    """You can roll it, spin it, squeeze it, stretch it... It's a lime!"""

    def __init__(self, volume: int) -> None:
        self.suco = []
        rinds = list(range(volume))
        while rinds:
            self.suco.append(rinds.pop(randbelow(len(rinds))))

    def Roll(self, suco: list) -> list:
        """Rolls the lime."""
        assert len(suco) == len(self.suco)
        return [suco[i] for i in self.suco]

    def Spin(self, suco: list) -> list:
        """Spins the lime."""
        assert len(suco) == len(self.suco)
        return [suco[self.suco.index(i)] for i in range(len(self.suco))]

    def Squeeze(self, suco: list) -> list:
        """Squeezes the lime."""
        assert not len(suco) % (len(self.suco) - 1).bit_length()
        parts = (len(self.suco) - 1).bit_length()
        pieces = [suco[i : i + parts] for i in range(0, len(suco), parts)]
        pieces = [sum(j * 2**i for i, j in enumerate(k)) for k in pieces]
        pieces = [self.suco[i] for i in pieces]
        pieces = [[(j >> i) & 1 for i in range(parts)] for j in pieces]
        return [i for j in pieces for i in j]

    def Stretch(self, suco: list) -> list:
        """Stretches the lime."""
        assert not len(suco) % (len(self.suco) - 1).bit_length()
        parts = (len(self.suco) - 1).bit_length()
        pieces = [suco[i : i + parts] for i in range(0, len(suco), parts)]
        pieces = [sum(j * 2**i for i, j in enumerate(k)) for k in pieces]
        pieces = [self.suco.index(i) for i in pieces]
        pieces = [[(j >> i) & 1 for i in range(parts)] for j in pieces]
        return [i for j in pieces for i in j]


if __name__ == "__main__":

    # Challenge parameters
    volume = 256
    sugars = 2
    iceCubes = 16

    # Challenge setup

    context(log_level="debug")
    io = process(["python3", "limeade.py"])
    io.recvuntil(b"Flag = ")
    flag_enc = io.recvline().decode()
    io.recvuntil(b"limes = ")
    limes_raw = io.recvline().decode()
    limes = [Lime(volume) for _ in range(3 * sugars + 1)]
    for i in range(3 * sugars + 1):
        limes[i].suco = list(B64Decode(limes_raw.split(".")[i]))

    s = token_bytes(32)
    key = [0] * 256
    secretIngredient = 0
    for i in range(256):
        d = 1 << i
        d0 = (1 << (limes[0].suco.index(i ^ 255) ^ 255)).to_bytes(32, "big")
        d2 = (1 << (limes[6].suco.index(i ^ 255) ^ 255)).to_bytes(32, "big")

        def Pour(a, b):
            if b < 0:
                b += 2**256
            b = b.to_bytes(256, "big")
            io.recvuntil(b"|  > ")
            io.sendline(b"p")
            io.sendline((B64Encode(a) + "." + B64Encode(b)).encode())
            io.recvuntil(b"cupFull = ")
            resp = B64Decode(io.recvline().decode()).rjust(32, b"\x00")
            return resp

        def Depour(a, b):
            if b < 0:
                b += 2**256
            b = b.to_bytes(256, "big")
            io.recvuntil(b"|  > ")
            io.sendline(b"d")
            io.sendline((B64Encode(a) + "." + B64Encode(b)).encode())
            io.recvuntil(b"cupEmpty = ")
            resp = B64Decode(io.recvline().decode()).rjust(32, b"\x00")
            return resp

        t = Pour(strxor(s, d0), d)
        t = Depour(strxor(t, d2), 0)
        t = Pour(strxor(t, d0), d)
        t = Depour(strxor(t, d2), 0)
        secretIngredient |= int(t != s) << i

    # guess the highest bit, 0 or 1
    print(
        AES.new(
            sha256(secretIngredient.to_bytes(volume // 8, "big")).digest(), AES.MODE_ECB
        ).decrypt(B64Decode(flag_enc))
    )
    secretIngredient += 1 << 255
    print(
        AES.new(
            sha256(secretIngredient.to_bytes(volume // 8, "big")).digest(), AES.MODE_ECB
        ).decrypt(B64Decode(flag_enc))
    )
```
