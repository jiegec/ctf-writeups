# Unicode bypass

## Common bypass

- [Unicode Block "Mathematical Alphanumeric Symbols"](https://www.compart.com/en/unicode/block/U+1D400)
    - `A` -> [`𝐀` (U+1D400)](https://www.compart.com/en/unicode/U+1D400)
    - `a` -> [`𝐚` (U+1D41A)](https://www.compart.com/en/unicode/U+1D41A)
- [Unicode Block "Alphabetic Presentation Forms"](https://www.compart.com/en/unicode/block/U+FB00)
    - `fl` -> [`ﬂ` (U+FB02)](https://www.compart.com/en/unicode/U+FB02), e.g. `ﬂag`
- [Unicode Block "Halfwidth and Fullwidth Forms"](https://www.compart.com/en/unicode/block/U+FF00)
    - `A` -> [`Ａ` (U+FF21)](https://www.compart.com/en/unicode/U+FF21)
    - `_` -> [`＿` (U+FF3F)](https://www.compart.com/en/unicode/U+FF3F), e.g. `_＿builtins＿＿` (cannot be used for the first character)
    - `a` -> [`ａ` (U+FF41)](https://www.compart.com/en/unicode/U+FF41), e.g. `ｏｓ`
- [Unicode Block "Number Forms"](https://www.compart.com/en/unicode/block/U+2150)
    - `VI` -> [`Ⅵ` (U+2165)](https://www.compart.com/en/unicode/U+2165)
    - `ii` -> [`ⅱ` (U+2171)](https://www.compart.com/en/unicode/U+2171)
    - `ix` -> [`ⅸ` (U+2178)](https://www.compart.com/en/unicode/U+2178)
    - `xi` -> [`ⅺ` (U+217A)](https://www.compart.com/en/unicode/U+217A), e.g. `eⅺt`
    - `xii` -> [`ⅻ` (U+217B)](https://www.compart.com/en/unicode/U+217B)

## Reduce length

Sometimes we can reduce length by unicode bypass:

```python
import unicodedata
import string
from collections import defaultdict

mapping = defaultdict(list)
for ch in range(0x110000):
    nfkc_text = unicodedata.normalize("NFKC", chr(ch))
    if all(c in string.printable for c in nfkc_text):
        # some characters are not working
        try:
            eval("_" + chr(ch))
        except SyntaxError as e:
            # bad
            continue
            pass
        except Exception as e:
            pass
        mapping[nfkc_text].append(chr(ch))


def find_shortest(s):
    res = []
    for i in range(len(s)):
        # case 1: no mapping happened
        if i > 0:
            new_res = res[i - 1] + s[i]
        else:
            new_res = s[i]
        # case 2: a suffix of length j is mapped
        for j in range(2, i + 2):
            part = s[i - j + 1 : i + 1]
            if part in mapping:
                if i - j + 1 > 0:
                    temp = res[i - j] + mapping[part][0]
                else:
                    temp = mapping[part][0]
                # found better solution
                if len(temp) < len(new_res):
                    new_res = temp
        res.append(new_res)
    return res[-1]


for function in __builtins__.__dict__:
    res = find_shortest(function)
    if len(res) < len(function):
        print(function, res, f"{len(res)} < {len(function)}")
```

Result:

```
ascii ascⅱ 4 < 5
divmod dⅳmod 5 < 6
isinstance isinﬅance 9 < 10
memoryview memoryⅵew 9 < 10
filter ﬁlter 5 < 6
float ﬂoat 4 < 5
list liﬅ 3 < 4
staticmethod ﬅaticmethod 11 < 12
str ﬅr 2 < 3
GeneratorExit GeneratorEⅺt 12 < 13
SystemExit SyﬅemEⅺt 8 < 10
EnvironmentError EnⅵronmentError 15 < 16
OverflowError OverﬂowError 12 < 13
ZeroDivisionError ZeroDⅳisionError 16 < 17
SystemError SyﬅemError 10 < 11
BufferError BuﬀerError 10 < 11
FileExistsError FileEⅺﬅsError 13 < 15
exit eⅺt 3 < 4
```

## Full mapping

Print all characters that map to ascii printables after NFKC normalization:

```python
import unicodedata
import string
from collections import defaultdict

mapping = defaultdict(list)
for ch in range(0x110000):
    nfkc_text = unicodedata.normalize("NFKC", chr(ch))
    if all(c in string.printable for c in nfkc_text):
        if nfkc_text != chr(ch):
            # some characters are not working
            try:
                eval("_" + chr(ch))
            except SyntaxError as e:
                # bad
                continue
                pass
            except Exception as e:
                pass
            mapping[nfkc_text].append(chr(ch))

for key in sorted(mapping.keys()):
    print("-", f"`{key}`:", ",".join(f"`{ch}` (U+{ord(ch):X})" for ch in mapping[key]))
```

Result:

- `0`: `０` (U+FF10),`𝟎` (U+1D7CE),`𝟘` (U+1D7D8),`𝟢` (U+1D7E2),`𝟬` (U+1D7EC),`𝟶` (U+1D7F6),`🯰` (U+1FBF0)
- `1`: `１` (U+FF11),`𝟏` (U+1D7CF),`𝟙` (U+1D7D9),`𝟣` (U+1D7E3),`𝟭` (U+1D7ED),`𝟷` (U+1D7F7),`🯱` (U+1FBF1)
- `2`: `２` (U+FF12),`𝟐` (U+1D7D0),`𝟚` (U+1D7DA),`𝟤` (U+1D7E4),`𝟮` (U+1D7EE),`𝟸` (U+1D7F8),`🯲` (U+1FBF2)
- `3`: `３` (U+FF13),`𝟑` (U+1D7D1),`𝟛` (U+1D7DB),`𝟥` (U+1D7E5),`𝟯` (U+1D7EF),`𝟹` (U+1D7F9),`🯳` (U+1FBF3)
- `4`: `４` (U+FF14),`𝟒` (U+1D7D2),`𝟜` (U+1D7DC),`𝟦` (U+1D7E6),`𝟰` (U+1D7F0),`𝟺` (U+1D7FA),`🯴` (U+1FBF4)
- `5`: `５` (U+FF15),`𝟓` (U+1D7D3),`𝟝` (U+1D7DD),`𝟧` (U+1D7E7),`𝟱` (U+1D7F1),`𝟻` (U+1D7FB),`🯵` (U+1FBF5)
- `6`: `６` (U+FF16),`𝟔` (U+1D7D4),`𝟞` (U+1D7DE),`𝟨` (U+1D7E8),`𝟲` (U+1D7F2),`𝟼` (U+1D7FC),`🯶` (U+1FBF6)
- `7`: `７` (U+FF17),`𝟕` (U+1D7D5),`𝟟` (U+1D7DF),`𝟩` (U+1D7E9),`𝟳` (U+1D7F3),`𝟽` (U+1D7FD),`🯷` (U+1FBF7)
- `8`: `８` (U+FF18),`𝟖` (U+1D7D6),`𝟠` (U+1D7E0),`𝟪` (U+1D7EA),`𝟴` (U+1D7F4),`𝟾` (U+1D7FE),`🯸` (U+1FBF8)
- `9`: `９` (U+FF19),`𝟗` (U+1D7D7),`𝟡` (U+1D7E1),`𝟫` (U+1D7EB),`𝟵` (U+1D7F5),`𝟿` (U+1D7FF),`🯹` (U+1FBF9)
- `A`: `ᴬ` (U+1D2C),`Ａ` (U+FF21),`𝐀` (U+1D400),`𝐴` (U+1D434),`𝑨` (U+1D468),`𝒜` (U+1D49C),`𝓐` (U+1D4D0),`𝔄` (U+1D504),`𝔸` (U+1D538),`𝕬` (U+1D56C),`𝖠` (U+1D5A0),`𝗔` (U+1D5D4),`𝘈` (U+1D608),`𝘼` (U+1D63C),`𝙰` (U+1D670)
- `B`: `ᴮ` (U+1D2E),`ℬ` (U+212C),`Ｂ` (U+FF22),`𝐁` (U+1D401),`𝐵` (U+1D435),`𝑩` (U+1D469),`𝓑` (U+1D4D1),`𝔅` (U+1D505),`𝔹` (U+1D539),`𝕭` (U+1D56D),`𝖡` (U+1D5A1),`𝗕` (U+1D5D5),`𝘉` (U+1D609),`𝘽` (U+1D63D),`𝙱` (U+1D671)
- `C`: `ℂ` (U+2102),`ℭ` (U+212D),`Ⅽ` (U+216D),`Ｃ` (U+FF23),`𝐂` (U+1D402),`𝐶` (U+1D436),`𝑪` (U+1D46A),`𝒞` (U+1D49E),`𝓒` (U+1D4D2),`𝕮` (U+1D56E),`𝖢` (U+1D5A2),`𝗖` (U+1D5D6),`𝘊` (U+1D60A),`𝘾` (U+1D63E),`𝙲` (U+1D672)
- `D`: `ᴰ` (U+1D30),`ⅅ` (U+2145),`Ⅾ` (U+216E),`Ｄ` (U+FF24),`𝐃` (U+1D403),`𝐷` (U+1D437),`𝑫` (U+1D46B),`𝒟` (U+1D49F),`𝓓` (U+1D4D3),`𝔇` (U+1D507),`𝔻` (U+1D53B),`𝕯` (U+1D56F),`𝖣` (U+1D5A3),`𝗗` (U+1D5D7),`𝘋` (U+1D60B),`𝘿` (U+1D63F),`𝙳` (U+1D673)
- `DZ`: `Ǳ` (U+1F1)
- `Dz`: `ǲ` (U+1F2)
- `E`: `ᴱ` (U+1D31),`ℰ` (U+2130),`Ｅ` (U+FF25),`𝐄` (U+1D404),`𝐸` (U+1D438),`𝑬` (U+1D46C),`𝓔` (U+1D4D4),`𝔈` (U+1D508),`𝔼` (U+1D53C),`𝕰` (U+1D570),`𝖤` (U+1D5A4),`𝗘` (U+1D5D8),`𝘌` (U+1D60C),`𝙀` (U+1D640),`𝙴` (U+1D674)
- `F`: `ℱ` (U+2131),`Ｆ` (U+FF26),`𝐅` (U+1D405),`𝐹` (U+1D439),`𝑭` (U+1D46D),`𝓕` (U+1D4D5),`𝔉` (U+1D509),`𝔽` (U+1D53D),`𝕱` (U+1D571),`𝖥` (U+1D5A5),`𝗙` (U+1D5D9),`𝘍` (U+1D60D),`𝙁` (U+1D641),`𝙵` (U+1D675)
- `G`: `ᴳ` (U+1D33),`Ｇ` (U+FF27),`𝐆` (U+1D406),`𝐺` (U+1D43A),`𝑮` (U+1D46E),`𝒢` (U+1D4A2),`𝓖` (U+1D4D6),`𝔊` (U+1D50A),`𝔾` (U+1D53E),`𝕲` (U+1D572),`𝖦` (U+1D5A6),`𝗚` (U+1D5DA),`𝘎` (U+1D60E),`𝙂` (U+1D642),`𝙶` (U+1D676)
- `H`: `ᴴ` (U+1D34),`ℋ` (U+210B),`ℌ` (U+210C),`ℍ` (U+210D),`Ｈ` (U+FF28),`𝐇` (U+1D407),`𝐻` (U+1D43B),`𝑯` (U+1D46F),`𝓗` (U+1D4D7),`𝕳` (U+1D573),`𝖧` (U+1D5A7),`𝗛` (U+1D5DB),`𝘏` (U+1D60F),`𝙃` (U+1D643),`𝙷` (U+1D677)
- `I`: `ᴵ` (U+1D35),`ℐ` (U+2110),`ℑ` (U+2111),`Ⅰ` (U+2160),`Ｉ` (U+FF29),`𝐈` (U+1D408),`𝐼` (U+1D43C),`𝑰` (U+1D470),`𝓘` (U+1D4D8),`𝕀` (U+1D540),`𝕴` (U+1D574),`𝖨` (U+1D5A8),`𝗜` (U+1D5DC),`𝘐` (U+1D610),`𝙄` (U+1D644),`𝙸` (U+1D678)
- `II`: `Ⅱ` (U+2161)
- `III`: `Ⅲ` (U+2162)
- `IJ`: `Ĳ` (U+132)
- `IV`: `Ⅳ` (U+2163)
- `IX`: `Ⅸ` (U+2168)
- `J`: `ᴶ` (U+1D36),`Ｊ` (U+FF2A),`𝐉` (U+1D409),`𝐽` (U+1D43D),`𝑱` (U+1D471),`𝒥` (U+1D4A5),`𝓙` (U+1D4D9),`𝔍` (U+1D50D),`𝕁` (U+1D541),`𝕵` (U+1D575),`𝖩` (U+1D5A9),`𝗝` (U+1D5DD),`𝘑` (U+1D611),`𝙅` (U+1D645),`𝙹` (U+1D679)
- `K`: `ᴷ` (U+1D37),`K` (U+212A),`Ｋ` (U+FF2B),`𝐊` (U+1D40A),`𝐾` (U+1D43E),`𝑲` (U+1D472),`𝒦` (U+1D4A6),`𝓚` (U+1D4DA),`𝔎` (U+1D50E),`𝕂` (U+1D542),`𝕶` (U+1D576),`𝖪` (U+1D5AA),`𝗞` (U+1D5DE),`𝘒` (U+1D612),`𝙆` (U+1D646),`𝙺` (U+1D67A)
- `L`: `ᴸ` (U+1D38),`ℒ` (U+2112),`Ⅼ` (U+216C),`Ｌ` (U+FF2C),`𝐋` (U+1D40B),`𝐿` (U+1D43F),`𝑳` (U+1D473),`𝓛` (U+1D4DB),`𝔏` (U+1D50F),`𝕃` (U+1D543),`𝕷` (U+1D577),`𝖫` (U+1D5AB),`𝗟` (U+1D5DF),`𝘓` (U+1D613),`𝙇` (U+1D647),`𝙻` (U+1D67B)
- `LJ`: `Ǉ` (U+1C7)
- `Lj`: `ǈ` (U+1C8)
- `M`: `ᴹ` (U+1D39),`ℳ` (U+2133),`Ⅿ` (U+216F),`Ｍ` (U+FF2D),`𝐌` (U+1D40C),`𝑀` (U+1D440),`𝑴` (U+1D474),`𝓜` (U+1D4DC),`𝔐` (U+1D510),`𝕄` (U+1D544),`𝕸` (U+1D578),`𝖬` (U+1D5AC),`𝗠` (U+1D5E0),`𝘔` (U+1D614),`𝙈` (U+1D648),`𝙼` (U+1D67C)
- `N`: `ᴺ` (U+1D3A),`ℕ` (U+2115),`Ｎ` (U+FF2E),`𝐍` (U+1D40D),`𝑁` (U+1D441),`𝑵` (U+1D475),`𝒩` (U+1D4A9),`𝓝` (U+1D4DD),`𝔑` (U+1D511),`𝕹` (U+1D579),`𝖭` (U+1D5AD),`𝗡` (U+1D5E1),`𝘕` (U+1D615),`𝙉` (U+1D649),`𝙽` (U+1D67D)
- `NJ`: `Ǌ` (U+1CA)
- `Nj`: `ǋ` (U+1CB)
- `O`: `ᴼ` (U+1D3C),`Ｏ` (U+FF2F),`𝐎` (U+1D40E),`𝑂` (U+1D442),`𝑶` (U+1D476),`𝒪` (U+1D4AA),`𝓞` (U+1D4DE),`𝔒` (U+1D512),`𝕆` (U+1D546),`𝕺` (U+1D57A),`𝖮` (U+1D5AE),`𝗢` (U+1D5E2),`𝘖` (U+1D616),`𝙊` (U+1D64A),`𝙾` (U+1D67E)
- `P`: `ᴾ` (U+1D3E),`ℙ` (U+2119),`Ｐ` (U+FF30),`𝐏` (U+1D40F),`𝑃` (U+1D443),`𝑷` (U+1D477),`𝒫` (U+1D4AB),`𝓟` (U+1D4DF),`𝔓` (U+1D513),`𝕻` (U+1D57B),`𝖯` (U+1D5AF),`𝗣` (U+1D5E3),`𝘗` (U+1D617),`𝙋` (U+1D64B),`𝙿` (U+1D67F)
- `Q`: `ℚ` (U+211A),`Ｑ` (U+FF31),`𝐐` (U+1D410),`𝑄` (U+1D444),`𝑸` (U+1D478),`𝒬` (U+1D4AC),`𝓠` (U+1D4E0),`𝔔` (U+1D514),`𝕼` (U+1D57C),`𝖰` (U+1D5B0),`𝗤` (U+1D5E4),`𝘘` (U+1D618),`𝙌` (U+1D64C),`𝚀` (U+1D680)
- `R`: `ᴿ` (U+1D3F),`ℛ` (U+211B),`ℜ` (U+211C),`ℝ` (U+211D),`Ｒ` (U+FF32),`𝐑` (U+1D411),`𝑅` (U+1D445),`𝑹` (U+1D479),`𝓡` (U+1D4E1),`𝕽` (U+1D57D),`𝖱` (U+1D5B1),`𝗥` (U+1D5E5),`𝘙` (U+1D619),`𝙍` (U+1D64D),`𝚁` (U+1D681)
- `S`: `Ｓ` (U+FF33),`𝐒` (U+1D412),`𝑆` (U+1D446),`𝑺` (U+1D47A),`𝒮` (U+1D4AE),`𝓢` (U+1D4E2),`𝔖` (U+1D516),`𝕊` (U+1D54A),`𝕾` (U+1D57E),`𝖲` (U+1D5B2),`𝗦` (U+1D5E6),`𝘚` (U+1D61A),`𝙎` (U+1D64E),`𝚂` (U+1D682)
- `T`: `ᵀ` (U+1D40),`Ｔ` (U+FF34),`𝐓` (U+1D413),`𝑇` (U+1D447),`𝑻` (U+1D47B),`𝒯` (U+1D4AF),`𝓣` (U+1D4E3),`𝔗` (U+1D517),`𝕋` (U+1D54B),`𝕿` (U+1D57F),`𝖳` (U+1D5B3),`𝗧` (U+1D5E7),`𝘛` (U+1D61B),`𝙏` (U+1D64F),`𝚃` (U+1D683)
- `U`: `ᵁ` (U+1D41),`Ｕ` (U+FF35),`𝐔` (U+1D414),`𝑈` (U+1D448),`𝑼` (U+1D47C),`𝒰` (U+1D4B0),`𝓤` (U+1D4E4),`𝔘` (U+1D518),`𝕌` (U+1D54C),`𝖀` (U+1D580),`𝖴` (U+1D5B4),`𝗨` (U+1D5E8),`𝘜` (U+1D61C),`𝙐` (U+1D650),`𝚄` (U+1D684)
- `V`: `Ⅴ` (U+2164),`ⱽ` (U+2C7D),`Ｖ` (U+FF36),`𝐕` (U+1D415),`𝑉` (U+1D449),`𝑽` (U+1D47D),`𝒱` (U+1D4B1),`𝓥` (U+1D4E5),`𝔙` (U+1D519),`𝕍` (U+1D54D),`𝖁` (U+1D581),`𝖵` (U+1D5B5),`𝗩` (U+1D5E9),`𝘝` (U+1D61D),`𝙑` (U+1D651),`𝚅` (U+1D685)
- `VI`: `Ⅵ` (U+2165)
- `VII`: `Ⅶ` (U+2166)
- `VIII`: `Ⅷ` (U+2167)
- `W`: `ᵂ` (U+1D42),`Ｗ` (U+FF37),`𝐖` (U+1D416),`𝑊` (U+1D44A),`𝑾` (U+1D47E),`𝒲` (U+1D4B2),`𝓦` (U+1D4E6),`𝔚` (U+1D51A),`𝕎` (U+1D54E),`𝖂` (U+1D582),`𝖶` (U+1D5B6),`𝗪` (U+1D5EA),`𝘞` (U+1D61E),`𝙒` (U+1D652),`𝚆` (U+1D686)
- `X`: `Ⅹ` (U+2169),`Ｘ` (U+FF38),`𝐗` (U+1D417),`𝑋` (U+1D44B),`𝑿` (U+1D47F),`𝒳` (U+1D4B3),`𝓧` (U+1D4E7),`𝔛` (U+1D51B),`𝕏` (U+1D54F),`𝖃` (U+1D583),`𝖷` (U+1D5B7),`𝗫` (U+1D5EB),`𝘟` (U+1D61F),`𝙓` (U+1D653),`𝚇` (U+1D687)
- `XI`: `Ⅺ` (U+216A)
- `XII`: `Ⅻ` (U+216B)
- `Y`: `Ｙ` (U+FF39),`𝐘` (U+1D418),`𝑌` (U+1D44C),`𝒀` (U+1D480),`𝒴` (U+1D4B4),`𝓨` (U+1D4E8),`𝔜` (U+1D51C),`𝕐` (U+1D550),`𝖄` (U+1D584),`𝖸` (U+1D5B8),`𝗬` (U+1D5EC),`𝘠` (U+1D620),`𝙔` (U+1D654),`𝚈` (U+1D688)
- `Z`: `ℤ` (U+2124),`ℨ` (U+2128),`Ｚ` (U+FF3A),`𝐙` (U+1D419),`𝑍` (U+1D44D),`𝒁` (U+1D481),`𝒵` (U+1D4B5),`𝓩` (U+1D4E9),`𝖅` (U+1D585),`𝖹` (U+1D5B9),`𝗭` (U+1D5ED),`𝘡` (U+1D621),`𝙕` (U+1D655),`𝚉` (U+1D689)
- `_`: `︳` (U+FE33),`︴` (U+FE34),`﹍` (U+FE4D),`﹎` (U+FE4E),`﹏` (U+FE4F),`＿` (U+FF3F)
- `a`: `ª` (U+AA),`ᵃ` (U+1D43),`ₐ` (U+2090),`ａ` (U+FF41),`𝐚` (U+1D41A),`𝑎` (U+1D44E),`𝒂` (U+1D482),`𝒶` (U+1D4B6),`𝓪` (U+1D4EA),`𝔞` (U+1D51E),`𝕒` (U+1D552),`𝖆` (U+1D586),`𝖺` (U+1D5BA),`𝗮` (U+1D5EE),`𝘢` (U+1D622),`𝙖` (U+1D656),`𝚊` (U+1D68A)
- `b`: `ᵇ` (U+1D47),`ｂ` (U+FF42),`𝐛` (U+1D41B),`𝑏` (U+1D44F),`𝒃` (U+1D483),`𝒷` (U+1D4B7),`𝓫` (U+1D4EB),`𝔟` (U+1D51F),`𝕓` (U+1D553),`𝖇` (U+1D587),`𝖻` (U+1D5BB),`𝗯` (U+1D5EF),`𝘣` (U+1D623),`𝙗` (U+1D657),`𝚋` (U+1D68B)
- `c`: `ᶜ` (U+1D9C),`ⅽ` (U+217D),`ｃ` (U+FF43),`𝐜` (U+1D41C),`𝑐` (U+1D450),`𝒄` (U+1D484),`𝒸` (U+1D4B8),`𝓬` (U+1D4EC),`𝔠` (U+1D520),`𝕔` (U+1D554),`𝖈` (U+1D588),`𝖼` (U+1D5BC),`𝗰` (U+1D5F0),`𝘤` (U+1D624),`𝙘` (U+1D658),`𝚌` (U+1D68C)
- `d`: `ᵈ` (U+1D48),`ⅆ` (U+2146),`ⅾ` (U+217E),`ｄ` (U+FF44),`𝐝` (U+1D41D),`𝑑` (U+1D451),`𝒅` (U+1D485),`𝒹` (U+1D4B9),`𝓭` (U+1D4ED),`𝔡` (U+1D521),`𝕕` (U+1D555),`𝖉` (U+1D589),`𝖽` (U+1D5BD),`𝗱` (U+1D5F1),`𝘥` (U+1D625),`𝙙` (U+1D659),`𝚍` (U+1D68D)
- `dz`: `ǳ` (U+1F3)
- `e`: `ᵉ` (U+1D49),`ₑ` (U+2091),`ℯ` (U+212F),`ⅇ` (U+2147),`ｅ` (U+FF45),`𝐞` (U+1D41E),`𝑒` (U+1D452),`𝒆` (U+1D486),`𝓮` (U+1D4EE),`𝔢` (U+1D522),`𝕖` (U+1D556),`𝖊` (U+1D58A),`𝖾` (U+1D5BE),`𝗲` (U+1D5F2),`𝘦` (U+1D626),`𝙚` (U+1D65A),`𝚎` (U+1D68E)
- `f`: `ᶠ` (U+1DA0),`ｆ` (U+FF46),`𝐟` (U+1D41F),`𝑓` (U+1D453),`𝒇` (U+1D487),`𝒻` (U+1D4BB),`𝓯` (U+1D4EF),`𝔣` (U+1D523),`𝕗` (U+1D557),`𝖋` (U+1D58B),`𝖿` (U+1D5BF),`𝗳` (U+1D5F3),`𝘧` (U+1D627),`𝙛` (U+1D65B),`𝚏` (U+1D68F)
- `ff`: `ﬀ` (U+FB00)
- `ffi`: `ﬃ` (U+FB03)
- `ffl`: `ﬄ` (U+FB04)
- `fi`: `ﬁ` (U+FB01)
- `fl`: `ﬂ` (U+FB02)
- `g`: `ᵍ` (U+1D4D),`ℊ` (U+210A),`ｇ` (U+FF47),`𝐠` (U+1D420),`𝑔` (U+1D454),`𝒈` (U+1D488),`𝓰` (U+1D4F0),`𝔤` (U+1D524),`𝕘` (U+1D558),`𝖌` (U+1D58C),`𝗀` (U+1D5C0),`𝗴` (U+1D5F4),`𝘨` (U+1D628),`𝙜` (U+1D65C),`𝚐` (U+1D690)
- `h`: `ʰ` (U+2B0),`ₕ` (U+2095),`ℎ` (U+210E),`ｈ` (U+FF48),`𝐡` (U+1D421),`𝒉` (U+1D489),`𝒽` (U+1D4BD),`𝓱` (U+1D4F1),`𝔥` (U+1D525),`𝕙` (U+1D559),`𝖍` (U+1D58D),`𝗁` (U+1D5C1),`𝗵` (U+1D5F5),`𝘩` (U+1D629),`𝙝` (U+1D65D),`𝚑` (U+1D691)
- `i`: `ᵢ` (U+1D62),`ⁱ` (U+2071),`ℹ` (U+2139),`ⅈ` (U+2148),`ⅰ` (U+2170),`ｉ` (U+FF49),`𝐢` (U+1D422),`𝑖` (U+1D456),`𝒊` (U+1D48A),`𝒾` (U+1D4BE),`𝓲` (U+1D4F2),`𝔦` (U+1D526),`𝕚` (U+1D55A),`𝖎` (U+1D58E),`𝗂` (U+1D5C2),`𝗶` (U+1D5F6),`𝘪` (U+1D62A),`𝙞` (U+1D65E),`𝚒` (U+1D692)
- `ii`: `ⅱ` (U+2171)
- `iii`: `ⅲ` (U+2172)
- `ij`: `ĳ` (U+133)
- `iv`: `ⅳ` (U+2173)
- `ix`: `ⅸ` (U+2178)
- `j`: `ʲ` (U+2B2),`ⅉ` (U+2149),`ⱼ` (U+2C7C),`ｊ` (U+FF4A),`𝐣` (U+1D423),`𝑗` (U+1D457),`𝒋` (U+1D48B),`𝒿` (U+1D4BF),`𝓳` (U+1D4F3),`𝔧` (U+1D527),`𝕛` (U+1D55B),`𝖏` (U+1D58F),`𝗃` (U+1D5C3),`𝗷` (U+1D5F7),`𝘫` (U+1D62B),`𝙟` (U+1D65F),`𝚓` (U+1D693)
- `k`: `ᵏ` (U+1D4F),`ₖ` (U+2096),`ｋ` (U+FF4B),`𝐤` (U+1D424),`𝑘` (U+1D458),`𝒌` (U+1D48C),`𝓀` (U+1D4C0),`𝓴` (U+1D4F4),`𝔨` (U+1D528),`𝕜` (U+1D55C),`𝖐` (U+1D590),`𝗄` (U+1D5C4),`𝗸` (U+1D5F8),`𝘬` (U+1D62C),`𝙠` (U+1D660),`𝚔` (U+1D694)
- `l`: `ˡ` (U+2E1),`ₗ` (U+2097),`ℓ` (U+2113),`ⅼ` (U+217C),`ｌ` (U+FF4C),`𝐥` (U+1D425),`𝑙` (U+1D459),`𝒍` (U+1D48D),`𝓁` (U+1D4C1),`𝓵` (U+1D4F5),`𝔩` (U+1D529),`𝕝` (U+1D55D),`𝖑` (U+1D591),`𝗅` (U+1D5C5),`𝗹` (U+1D5F9),`𝘭` (U+1D62D),`𝙡` (U+1D661),`𝚕` (U+1D695)
- `lj`: `ǉ` (U+1C9)
- `m`: `ᵐ` (U+1D50),`ₘ` (U+2098),`ⅿ` (U+217F),`ｍ` (U+FF4D),`𝐦` (U+1D426),`𝑚` (U+1D45A),`𝒎` (U+1D48E),`𝓂` (U+1D4C2),`𝓶` (U+1D4F6),`𝔪` (U+1D52A),`𝕞` (U+1D55E),`𝖒` (U+1D592),`𝗆` (U+1D5C6),`𝗺` (U+1D5FA),`𝘮` (U+1D62E),`𝙢` (U+1D662),`𝚖` (U+1D696)
- `n`: `ⁿ` (U+207F),`ₙ` (U+2099),`ｎ` (U+FF4E),`𝐧` (U+1D427),`𝑛` (U+1D45B),`𝒏` (U+1D48F),`𝓃` (U+1D4C3),`𝓷` (U+1D4F7),`𝔫` (U+1D52B),`𝕟` (U+1D55F),`𝖓` (U+1D593),`𝗇` (U+1D5C7),`𝗻` (U+1D5FB),`𝘯` (U+1D62F),`𝙣` (U+1D663),`𝚗` (U+1D697)
- `nj`: `ǌ` (U+1CC)
- `o`: `º` (U+BA),`ᵒ` (U+1D52),`ₒ` (U+2092),`ℴ` (U+2134),`ｏ` (U+FF4F),`𝐨` (U+1D428),`𝑜` (U+1D45C),`𝒐` (U+1D490),`𝓸` (U+1D4F8),`𝔬` (U+1D52C),`𝕠` (U+1D560),`𝖔` (U+1D594),`𝗈` (U+1D5C8),`𝗼` (U+1D5FC),`𝘰` (U+1D630),`𝙤` (U+1D664),`𝚘` (U+1D698)
- `p`: `ᵖ` (U+1D56),`ₚ` (U+209A),`ｐ` (U+FF50),`𝐩` (U+1D429),`𝑝` (U+1D45D),`𝒑` (U+1D491),`𝓅` (U+1D4C5),`𝓹` (U+1D4F9),`𝔭` (U+1D52D),`𝕡` (U+1D561),`𝖕` (U+1D595),`𝗉` (U+1D5C9),`𝗽` (U+1D5FD),`𝘱` (U+1D631),`𝙥` (U+1D665),`𝚙` (U+1D699)
- `q`: `ｑ` (U+FF51),`𝐪` (U+1D42A),`𝑞` (U+1D45E),`𝒒` (U+1D492),`𝓆` (U+1D4C6),`𝓺` (U+1D4FA),`𝔮` (U+1D52E),`𝕢` (U+1D562),`𝖖` (U+1D596),`𝗊` (U+1D5CA),`𝗾` (U+1D5FE),`𝘲` (U+1D632),`𝙦` (U+1D666),`𝚚` (U+1D69A)
- `r`: `ʳ` (U+2B3),`ᵣ` (U+1D63),`ｒ` (U+FF52),`𝐫` (U+1D42B),`𝑟` (U+1D45F),`𝒓` (U+1D493),`𝓇` (U+1D4C7),`𝓻` (U+1D4FB),`𝔯` (U+1D52F),`𝕣` (U+1D563),`𝖗` (U+1D597),`𝗋` (U+1D5CB),`𝗿` (U+1D5FF),`𝘳` (U+1D633),`𝙧` (U+1D667),`𝚛` (U+1D69B)
- `s`: `ſ` (U+17F),`ˢ` (U+2E2),`ₛ` (U+209B),`ｓ` (U+FF53),`𝐬` (U+1D42C),`𝑠` (U+1D460),`𝒔` (U+1D494),`𝓈` (U+1D4C8),`𝓼` (U+1D4FC),`𝔰` (U+1D530),`𝕤` (U+1D564),`𝖘` (U+1D598),`𝗌` (U+1D5CC),`𝘀` (U+1D600),`𝘴` (U+1D634),`𝙨` (U+1D668),`𝚜` (U+1D69C)
- `st`: `ﬅ` (U+FB05),`ﬆ` (U+FB06)
- `t`: `ᵗ` (U+1D57),`ₜ` (U+209C),`ｔ` (U+FF54),`𝐭` (U+1D42D),`𝑡` (U+1D461),`𝒕` (U+1D495),`𝓉` (U+1D4C9),`𝓽` (U+1D4FD),`𝔱` (U+1D531),`𝕥` (U+1D565),`𝖙` (U+1D599),`𝗍` (U+1D5CD),`𝘁` (U+1D601),`𝘵` (U+1D635),`𝙩` (U+1D669),`𝚝` (U+1D69D)
- `u`: `ᵘ` (U+1D58),`ᵤ` (U+1D64),`ｕ` (U+FF55),`𝐮` (U+1D42E),`𝑢` (U+1D462),`𝒖` (U+1D496),`𝓊` (U+1D4CA),`𝓾` (U+1D4FE),`𝔲` (U+1D532),`𝕦` (U+1D566),`𝖚` (U+1D59A),`𝗎` (U+1D5CE),`𝘂` (U+1D602),`𝘶` (U+1D636),`𝙪` (U+1D66A),`𝚞` (U+1D69E)
- `v`: `ᵛ` (U+1D5B),`ᵥ` (U+1D65),`ⅴ` (U+2174),`ｖ` (U+FF56),`𝐯` (U+1D42F),`𝑣` (U+1D463),`𝒗` (U+1D497),`𝓋` (U+1D4CB),`𝓿` (U+1D4FF),`𝔳` (U+1D533),`𝕧` (U+1D567),`𝖛` (U+1D59B),`𝗏` (U+1D5CF),`𝘃` (U+1D603),`𝘷` (U+1D637),`𝙫` (U+1D66B),`𝚟` (U+1D69F)
- `vi`: `ⅵ` (U+2175)
- `vii`: `ⅶ` (U+2176)
- `viii`: `ⅷ` (U+2177)
- `w`: `ʷ` (U+2B7),`ｗ` (U+FF57),`𝐰` (U+1D430),`𝑤` (U+1D464),`𝒘` (U+1D498),`𝓌` (U+1D4CC),`𝔀` (U+1D500),`𝔴` (U+1D534),`𝕨` (U+1D568),`𝖜` (U+1D59C),`𝗐` (U+1D5D0),`𝘄` (U+1D604),`𝘸` (U+1D638),`𝙬` (U+1D66C),`𝚠` (U+1D6A0)
- `x`: `ˣ` (U+2E3),`ₓ` (U+2093),`ⅹ` (U+2179),`ｘ` (U+FF58),`𝐱` (U+1D431),`𝑥` (U+1D465),`𝒙` (U+1D499),`𝓍` (U+1D4CD),`𝔁` (U+1D501),`𝔵` (U+1D535),`𝕩` (U+1D569),`𝖝` (U+1D59D),`𝗑` (U+1D5D1),`𝘅` (U+1D605),`𝘹` (U+1D639),`𝙭` (U+1D66D),`𝚡` (U+1D6A1)
- `xi`: `ⅺ` (U+217A)
- `xii`: `ⅻ` (U+217B)
- `y`: `ʸ` (U+2B8),`ｙ` (U+FF59),`𝐲` (U+1D432),`𝑦` (U+1D466),`𝒚` (U+1D49A),`𝓎` (U+1D4CE),`𝔂` (U+1D502),`𝔶` (U+1D536),`𝕪` (U+1D56A),`𝖞` (U+1D59E),`𝗒` (U+1D5D2),`𝘆` (U+1D606),`𝘺` (U+1D63A),`𝙮` (U+1D66E),`𝚢` (U+1D6A2)
- `z`: `ᶻ` (U+1DBB),`ｚ` (U+FF5A),`𝐳` (U+1D433),`𝑧` (U+1D467),`𝒛` (U+1D49B),`𝓏` (U+1D4CF),`𝔃` (U+1D503),`𝔷` (U+1D537),`𝕫` (U+1D56B),`𝖟` (U+1D59F),`𝗓` (U+1D5D3),`𝘇` (U+1D607),`𝘻` (U+1D63B),`𝙯` (U+1D66F),`𝚣` (U+1D6A3)

