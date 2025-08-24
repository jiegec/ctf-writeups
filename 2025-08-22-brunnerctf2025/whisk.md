# Whisk

```
Crypto

Difficulty: Beginner
Author: rvsms

Someone tried sabotaging our operation by "whisking” away the secret ingredient for the perfect brunsviger. All that's left on the workbench is this sticky note full of pastry-themed symbols and random letters.

Can you help us recover the secret ingredient?
```

Attachment:

```
DR🥐 C🥐TZ🥐D 🧁SXZ🥐A🧁🥐SD 🧁C 🍰KE🍰FC K🍩M🥐. D🍩 O🍰Q🥐 🍰 Y🥐ZP🥐TD
OZ🥖SCM🧁X🥐Z, H🥐KD O🥖DD🥐Z E🧁DR OZ🍩ES C🥖X🍰Z, Y🍩🥖Z 🧁D 🍩M🥐Z DR🥐 E🍰ZH
A🍩🥖XR, 🍰SA K🥐D DR🥐 CFZ🥖Y C🥐🥐Y 🧁SD🍩 🥐M🥐ZF T🍩ZS🥐Z. D🍰CD🥐, CH🧁K🥐,
🍰SA Z🥐H🥐HO🥐Z: CR🍰Z🧁SX Y🍰CDZF N🍩F 🧁C H🍰SA🍰D🍩ZF.
OZ🥖SS🥐Z{S0_H0Z3_K🥖HYF_T1YR3Z}
```

Find the character mapping through trial and error:

```python
text = """DR🥐 C🥐TZ🥐D 🧁SXZ🥐A🧁🥐SD 🧁C 🍰KE🍰FC K🍩M🥐. D🍩 O🍰Q🥐 🍰 Y🥐ZP🥐TD
OZ🥖SCM🧁X🥐Z, H🥐KD O🥖DD🥐Z E🧁DR OZ🍩ES C🥖X🍰Z, Y🍩🥖Z 🧁D 🍩M🥐Z DR🥐 E🍰ZH
A🍩🥖XR, 🍰SA K🥐D DR🥐 CFZ🥖Y C🥐🥐Y 🧁SD🍩 🥐M🥐ZF T🍩ZS🥐Z. D🍰CD🥐, CH🧁K🥐,
🍰SA Z🥐H🥐HO🥐Z: CR🍰Z🧁SX Y🍰CDZF N🍩F 🧁C H🍰SA🍰D🍩ZF.
OZ🥖SS🥐Z{S0_H0Z3_K🥖HYF_T1YR3Z}"""

mapping = {
    "O": "b",
    "S": "n",
    "Z": "r",
    "🥐": "e",
    "🥖": "u",
    "A": "d",
    "C": "s",
    "D": "t",
    "E": "w",
    "F": "y",
    "H": "m",
    "K": "l",
    "M": "v",
    "N": "j",
    "P": "f",
    "Q": "k",
    "R": "h",
    "T": "c",
    "X": "g",
    "Y": "p",
    "🍩": "o",
    "🍰": "a",
    "🧁": "i",
}
for ch in text:
    if ch in mapping:
        print(mapping[ch], end="")
    else:
        print(ch, end="")
```

Output:

```
the secret ingredient is always love. to bake a perfect
brunsviger, melt butter with brown sugar, pour it over the warm
dough, and let the syrup seep into every corner. taste, smile,
and remember: sharing pastry joy is mandatory.
brunner{n0_m0r3_lumpy_c1ph3r}
```
