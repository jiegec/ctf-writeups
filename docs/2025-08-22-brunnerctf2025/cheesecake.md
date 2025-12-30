# Cheesecake

```
Difficulty: 🧀
Author: Bond

Whoever thought 💡 of mixing 👀 cheese 🧀 with cake 🧁 it sure is easy on the palate 😋
```

Attachment:

```python
# Cheese and cake together - really?

from random import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from gostcrypto import gostcipher
from Crypto.Cipher import ARC4
from Crypto.Hash import MD2


# If there is really cheese in this cake, it should be flagged!
def get_FLAG_from_HEX(hexcode):
    """Input the hexadecimal code string of sufficient length to remove obfuscation and return 
    the decrypted flag as a plaintext string starting with 'brunner{' and ending with '}'."""
    assert len(hexcode) % 32 == 0
    bytes_data = bytes(int(b,16) for b in hexcode).hex().encode()
    c = 42407562439075681492143456259122041922599228616502828873021088919446915392428 
    d = 5186683434748896574370264474720365034728611610795088756404643529414136307618
    plaintext = SPECIAL_technique(bytes_data, c, d)
    return plaintext.decode()
 
def SPECIAL_technique(bytes_data, c, d):
    """There's a special cooking technique that we'll be using a couple of times for this recipe."""
    xor_bytes = bytearray()
    for i in range(0, len(bytes_data)//32):
        block = bytes_data[i*32:(i+1)*32]
        xor_bytes.extend(x ^ y for x, y in zip(block, (c - (-1)**i * d).to_bytes(32, 'big')))
    return xor_bytes


# Other than that I suggest we try running with the recipe as is!


def ranDOCm(func):
    """First, lets be modern and do a bit of mental preparation before starting to cook:
    The secret behind consistently stable cooking, is to modulate your technique to conform 
    to the recipe precisely as documented thereby minimizing what is random."""
    docstring_int = int.from_bytes(''.join(func.__doc__.split()).encode(), 'big')
    pseude_random_int = docstring_int % 11
    return pseude_random_int

def graham_crackeRSA(plaintext, seed):
    """Crush the graham crackers. (For making the crust.)"""
    prng = Random(seed)
    def randfunc(n): return prng.getrandbits(n * 8).to_bytes(n, 'big')
    key = RSA.generate(1024, randfunc=randfunc)
    pub_n, pub_e = key.n, key.e
    m_int = int.from_bytes(plaintext.encode(), 'big')
    c_int = pow(m_int, pub_e, pub_n)
    ciphertext = c_int.to_bytes((c_int.bit_length() + 7) // 8, 'big')
    return ciphertext

# If you're in an experimental mood, you could try mixing beaten egg with milk and sugar to pour over 
# the crackers as an added solution giving breadtexture to the crust.
def ADDed_SOLUTION_giving_bREADMETEXTure(ciphertext, e):
    """Splits a 128 byte ciphertext into two blocks and xors them with values, which besides serving as 
    further encryption intermediately also turns the first block into bytes that if decoded contains 
    plaintext describing in full detail how to get the flag in this challenge."""
    assert len(ciphertext) == 128
    c = 46412520328440256871399753615737168429362885041489783567894921161800073479497
    d = 30147310566698376871947829873776459834598978229983782629303180618977163687145
    SOLUTION_READMETEXT = SPECIAL_technique(ciphertext[:64], c, d)
    residual_ciphertext = SPECIAL_technique(ciphertext[64:], c, d)
    ciphertext = bytes(b ^ e for b in (SOLUTION_READMETEXT + residual_ciphertext))
    return ciphertext

def melted_BITter(ciphertext, shift):
    """Melt the butter, and mix it with the graham cracker crumbs."""
    ciphertext = bytes(((b << shift%8) & 0xFF) | (b >> (8 - shift%8)) for b in ciphertext)
    return ciphertext

def ground_CAESARdamom(ciphertext, key):
    """Ground cardamom lends a warm, citrus-floral spice (for an intriguingly aromatic depth, 
    reminiscent of e.g. Scandinavian and Middle_Eastern desserts)."""
    ciphertext = bytes((b + key) % 256 for b in ciphertext)
    return ciphertext

def an_egGOST(ciphertext, int_key):
    """An egg is needed to help in binding the ingredients together."""
    key = int_key.to_bytes(32, 'big')
    cipher = gostcipher.new("kuznechik", key, gostcipher.MODE_CTR, init_vect=b"\0"*8)
    ciphertext = cipher.encrypt(ciphertext)
    return ciphertext

def sour_STREAM(ciphertext, key_byte):
    """Sour cream is commonly a central ingredient in a lot of cheesecake recipes."""
    key = bytes([key_byte])
    cipher = ARC4.new(key)
    ciphertext = cipher.encrypt(ciphertext)
    return ciphertext

def vanilla_eXORtract(ciphertext, seed):
    """Vanilla extract is often used: For enhancing the flavor of the cheesecake."""
    key = bytes(Random(seed:=seed+1).getrandbits(8) for _ in range(len(ciphertext)))
    ciphertext = bytes([b ^ k for b, k in zip(ciphertext, key)])
    return ciphertext

def cAESugar(ciphertext, key_byte):
    """Cane sugar is often used in cheesecake recipes (to add sweetness to it)."""
    key = bytes([key_byte] * 16)
    ciphertext = AES.new(key, AES.MODE_ECB).encrypt(ciphertext)
    return ciphertext

def beat_INTEGERgredients(ciphertext, int_key):
    """After adding several different things it's a good time to beat the ingredients together."""
    s = """,&6y5jz*r~6BR `|FQ39*So7w`,&oC*1^PZhCKp}UT. C^tgoVBRb$z`*Zpa)XB>|b^%MO~6~IR_whvM!}|mA |@jj090!*gP;?Qf*Cj0$"{@5&[HjpVTnig|>?]Q$CT4}{S3i8iC[kUq2GfW3\\>iu:O30qp"""
    s2i = lambda s:sum((d:=[chr(i) for i in range(32,127)]).index(c)*len(d)**i for i,c in enumerate(s[::-1]))
    i = s2i(s)//int_key
    n = int.from_bytes(ciphertext, 'big')
    ciphertext = (m:=n-i).to_bytes((m.bit_length() + 7) // 8, 'big')
    return ciphertext

def cheese_cake_MIX():
    """And now for the big show:"""
    steps = [graham_crackeRSA, ADDed_SOLUTION_giving_bREADMETEXTure, melted_BITter, ground_CAESARdamom, 
             an_egGOST, sour_STREAM, vanilla_eXORtract, cAESugar, beat_INTEGERgredients]

    # Doesn't every famous recipe have a secret ingredient? :)
    secret = 'REDACTED'
    custom_padding_removal = lambda s: s[: len(s) - 16 - int(s[-1], 16)*16]
    secret = custom_padding_removal(secret)
    mix = get_FLAG_from_HEX(secret)
    custom_padding = lambda s: ''.join(((p:= s + hex((112 - len(s)) // 16)[2:] * 16)[(j:= i%(len(p))): j+16] for i in range(0, 128, 16)))
    mix = custom_padding(mix)
    
    # Now follow the recipe step by step. 
    for step in steps: 
        mix = step(mix, ranDOCm(step))
    return mix

def creaMD2_cheese(ciphertext):
    """But finally of course we essentially need the cheese for it to be a cheese cake, after which we can now give it a try
    with that nice creamy layer simultaneously covering over any contained secrets ;)"""
    hexcode = MD2.new(ciphertext).hexdigest()
    return hexcode


# So let's give it a taste :-)
mix = cheese_cake_MIX()
hex = creaMD2_cheese(mix) 
assert hex == "8350e5a3e24c153df2275c9f80692773"
# Heeey, you know what, that turned out perfectly well after all! :-D
# Really has everything you need! :)
```

If we print the `mix` variable in every loop:

```python
for step in steps: 
    mix = step(mix, ranDOCm(step))
    print(mix)
return mix
```

There is a hint printed:

```python
from recipe import *; print("flag =  " + get_FLAG_from_HEX(hex))
```

So we just execute it, and get the flag: `brunner{7Urn5_0uT_th3Re_WasN7_4nY_SEcr3T5_4FtR_A1l_x)_Badum-tss}`
