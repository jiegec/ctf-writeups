# Unf33dMe

```
Easy structure but the choice of parameters make it as strong as a Babylonian defense.
```

Attachment:

```python
# source.sage
#!/usr/bin/env sage

import sys
from os import path

from Crypto.Hash import SHAKE256
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long


class Babylon:
    def __init__(self):
        self.setParams()
        self.genConstants()

    def setParams(self):
        self.exp = 3
        self.p = 65537
        self.nbytes = self.p.bit_length() // 8
        self.F = GF(self.p)
        self.state_size = 24
        self.rounds = 3

    def genConstants(self):
        shake = SHAKE256.new()
        shake.update(b"SNAKECTF")
        self.constants = []
        for _ in range(self.rounds):
            self.constants.append(self.F(int.from_bytes(shake.read(self.nbytes), 'big')))

    def decompose(self, message):
        state = []
        padded_message = pad(message, self.state_size * self.nbytes)
        for i in range(0, len(padded_message), self.nbytes):
            chunk = bytes_to_long(padded_message[i:i + self.nbytes])
            state.append(chunk)
        return state

    def random(self):
        return [self.F.random_element() for _ in range(self.state_size)]

    def shuffle(self, state):
        for i in range(0, self.state_size, 2):
            t = state[i]
            state[i] = state[i + 1]
            state[i + 1] = t
        return state

    def add(self, state, constant):
        return [state[i] + constant for i in range(self.state_size)]

    def xor(self, a, b):
        return [a[i] + b[i] for i in range(self.state_size)]

    def sbox(self, state):
        return [(state[i]) ^ self.exp for i in range(self.state_size)]

    def round(self, state, r):
        state = self.sbox(state)
        state = self.add(state, self.constants[r])
        return state

    def permute(self, state, key):
        state = self.xor(state, key)
        for r in range(self.rounds):
            state = self.round(state, r)
        return state

    def hash(self, message):
        input = self.decompose(message)
        IV = self.random()
        output = self.permute(input, IV)
        digest = self.xor(output, self.shuffle(input))
        return digest, IV


if __name__ == "__main__":
    out_dir = sys.argv[1]
    flag = sys.argv[2].encode()

    babylon = Babylon()
    assert len(flag) < babylon.state_size * babylon.nbytes, len(flag)

    digest, IV = babylon.hash(flag)

    with open(path.join(out_dir, "out.txt"), "w") as f:
        f.write(f"{digest}\n{IV}")
```

`out.txt`:

```
[46811, 17759, 35197, 49826, 47997, 19921, 63959, 11473, 49998, 4650, 19281, 25353, 14753, 11258, 22955, 59089, 53710, 26405, 12375, 51609, 54377, 39129, 39648, 2386]
[13854, 18805, 31728, 45272, 29837, 59039, 44283, 37121, 19303, 22579, 10471, 14257, 9696, 37124, 12335, 18051, 32556, 64472, 16417, 8752, 63725, 9534, 34534, 9679]
```

Reading the code, essentially we are solving a system of modular equations:

```
Eq(Mod(input_1 + (((input_0 + 13854)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 46811)
Eq(Mod(input_0 + (((input_1 + 18805)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 17759)
Eq(Mod(input_3 + (((input_2 + 31728)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 35197)
Eq(Mod(input_2 + (((input_3 + 45272)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 49826)
Eq(Mod(input_5 + (((input_4 + 29837)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 47997)
Eq(Mod(input_4 + (((input_5 + 59039)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 19921)
Eq(Mod(input_7 + (((input_6 + 44283)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 63959)
Eq(Mod(input_6 + (((input_7 + 37121)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 11473)
Eq(Mod(input_9 + (((input_8 + 19303)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 49998)
Eq(Mod(input_8 + (((input_9 + 22579)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 4650)
Eq(Mod(input_11 + (((input_10 + 10471)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 19281)
Eq(Mod(input_10 + (((input_11 + 14257)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 25353)
Eq(Mod(input_13 + (((input_12 + 9696)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 14753)
Eq(Mod(input_12 + (((input_13 + 37124)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 11258)
Eq(Mod(input_15 + (((input_14 + 12335)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 22955)
Eq(Mod(input_14 + (((input_15 + 18051)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 59089)
Eq(Mod(input_17 + (((input_16 + 32556)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 53710)
Eq(Mod(input_16 + (((input_17 + 64472)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 26405)
Eq(Mod(input_19 + (((input_18 + 16417)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 12375)
Eq(Mod(input_18 + (((input_19 + 8752)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 51609)
Eq(Mod(input_21 + (((input_20 + 63725)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 54377)
Eq(Mod(input_20 + (((input_21 + 9534)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 39129)
Eq(Mod(input_23 + (((input_22 + 34534)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 39648)
Eq(Mod(input_22 + (((input_23 + 9679)**3 + 43938)**3 + 28185)**3 + 5314, 65537), 2386)
```

The format is:

```
Eq(Mod(input_1 + (((input_0 + IV_0)**3 + 43938)**3 + 28185)**3 + 5314, 65537), digest_0)
Eq(Mod(input_0 + (((input_1 + IV_1)**3 + 43938)**3 + 28185)**3 + 5314, 65537), digest_1)
Eq(Mod(input_3 + (((input_2 + IV_2)**3 + 43938)**3 + 28185)**3 + 5314, 65537), digest_2)
Eq(Mod(input_2 + (((input_3 + IV_3)**3 + 43938)**3 + 28185)**3 + 5314, 65537), digest_3)
```

Se we can solve `input_0` and `input_1` by enumerating `input_0`, then repeat the process for all inputs:

```python
#!/usr/bin/env sage

import sympy as sp
from os import path

from Crypto.Hash import SHAKE256
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long, long_to_bytes


digest = [
    46811,
    17759,
    35197,
    49826,
    47997,
    19921,
    63959,
    11473,
    49998,
    4650,
    19281,
    25353,
    14753,
    11258,
    22955,
    59089,
    53710,
    26405,
    12375,
    51609,
    54377,
    39129,
    39648,
    2386,
]
IV = [
    13854,
    18805,
    31728,
    45272,
    29837,
    59039,
    44283,
    37121,
    19303,
    22579,
    10471,
    14257,
    9696,
    37124,
    12335,
    18051,
    32556,
    64472,
    16417,
    8752,
    63725,
    9534,
    34534,
    9679,
]

p = 65537
nbytes = p.bit_length() // 8
exp = 3
state_size = 24
rounds = 3

shake = SHAKE256.new()
shake.update(b"SNAKECTF")
constants = []
for _ in range(rounds):
    constants.append(int.from_bytes(shake.read(nbytes), "big") % p)

# permute
input = sp.symbols("input_0:24")
state = [(input[i] + IV[i]) for i in range(state_size)]
for r in range(rounds):
    state = [(state[i]) ** exp for i in range(state_size)]
    state = [state[i] + constants[r] for i in range(state_size)]

input_temp = list(input)
for i in range(0, state_size, 2):
    t = input_temp[i]
    input_temp[i] = input_temp[i + 1]
    input_temp[i + 1] = t

state = [(state[i] + input_temp[i]) % p for i in range(state_size)]
exprs = [sp.Eq(state[i], digest[i]) for i in range(state_size)]

for expr in exprs:
    print(expr)

# enumerate number in pairs
answer = [0] * state_size
for index in range(0, state_size, 2):
    for i in range(65537):
        # answer[index] == i, solve answer[index + 1]
        other = (
            digest[index]
            - (
                (((i + IV[index]) ** 3 + constants[0]) ** 3 + constants[1]) ** 3
                + constants[2]
            )
        ) % p
        # verify
        me = (
            digest[index + 1]
            - (
                (((other + IV[index + 1]) ** 3 + constants[0]) ** 3 + constants[1])
                ** 3
                + constants[2]
            )
        ) % p
        if i == me:
            # found
            # printable
            text_me = long_to_bytes(me)
            text_other = long_to_bytes(other)
            print("possible answer:", text_me, text_other)
```

Result:

```
possible answer: b'sn' b'ak'
possible answer: b'\xc6Q' b'z\x1d'
possible answer: b'\x18\x15' b'jR'
possible answer: b'eC' b'TF'
possible answer: b'{p' b'0l'
possible answer: b'3\x8a' b'\t\xc7'
possible answer: b'ys' b'_4'
possible answer: b'\x8c\xc4' b'\xaa\xaa'
possible answer: b'Y\xd3' b'$\x12'
possible answer: b'r3' b'_m'
possible answer: b'4g' b'1c'
possible answer: b'\x98\x90' b'\xb3]'
possible answer: b'\xee\xc7' b'\xd6\xa5'
possible answer: b'_:' b')_'
possible answer: b'c7' b'a5'
possible answer: b'\x19?' b'"\x85'
possible answer: b'F\x0b' b'\x99\xc6'
possible answer: b'c9' b'27'
possible answer: b'c1' b'3b'
possible answer: b'\xad\x1d' b'c\xa5'
possible answer: b'81' b'ff'
possible answer: b'}\x03' b'\x03\x03'
```

We need to drop some non-printable characters, so the flag is: `snakeCTF{p0lys_4r3_m4g1c_:)_c7a5c927c13b81ff}` with padding dropped.
