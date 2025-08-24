#  The Cryptographic Kitchen!

```
Difficulty: Easy
Author: H4N5

Our brand new baker, ElGamal, has whipped up the most wonderful cheesecake you could ever imagine. Seriously, it's so good it might encrypt your taste buds.

But... there's a problem. One mysterious ingredient is missing from the recipe!
Can you crack the code and figure out what ElGamal forgot to mix in?

The suspiciously scrambled recipe says this:

p  = 14912432766367177751
g  = 2784687438861268863
h  = 8201777436716393968
c1 = 12279519522290406516
c2 = 10734305369677133991

The flag is the recovered plaintext, wrapped in brunner{}.
Example: If you found c4rr0t5, the flag should be submitted as brunner{c4rr0t5}.
```

The numbers are small, solve discrete logarithm using sage:

```sage
p  = 14912432766367177751
g  = 2784687438861268863
h  = 8201777436716393968
c1 = 12279519522290406516
c2 = 10734305369677133991

# h = g ^ x mod p
# s = h ^ y mod p
# c1 = g ^ y mod p
# c2 = m * s mod p
R = Integers(p)
x = R(h).log(g)
s = pow(c1, x, p)
m = c2 * pow(s, -1, p) % p
print(bytes.fromhex(hex(m)[2:]))
```

Get flag: `brunner{buTT3r}`