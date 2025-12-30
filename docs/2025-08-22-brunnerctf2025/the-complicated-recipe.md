# The Complicated Recipe

```
Difficulty: Medium
Author: H4N5

I am not very good with numbers, but when it comes to baking, there is no limit. However, I found this recipe, but I cannot read it. One of my colleagues (Master Baker Feistel) told me this was one of his, but he would not help me decipher it. He just laughed and said, "DES is not for you to bake." I think he is foreign.

I have heard him say that DES and even "trois" DES are no longer safe enough, but he mentioned that his recipe was S-DES encrypted, which I assume means Super-DES. This should be impossible to decrypt without the key - right?

D1D74C5F5FDDD7ECD8B29ED8019DD801B7F2AB0128573FB2019D1C018FF2E001E7B7F2870128F28701ABF20112E0D8AB015957E79EA2
```

S-DES only has 10 bit keys, bruteforce:

```python
from sdes import encrypt, decrypt, generate_keys
import bitarray

c = bytes.fromhex("D1D74C5F5FDDD7ECD8B29ED8019DD801B7F2AB0128573FB2019D1C018FF2E001E7B7F2870128F28701ABF20112E0D8AB015957E79EA2")

for i in range(1024):
    bit = bin(i)[2:].zfill(10)
    key = bitarray.bitarray(bit)
    key1, key2 = generate_keys(key)
    decrypted = ""
    for ch in c:
        text = decrypt(bitarray.bitarray(bin(ch)[2:].zfill(8)), key1, key2)
        decrypted += chr(text.tobytes()[0])
    if "brunner" in decrypted:
        print("Decrypted:", decrypted)
```

Get flag: `brunner{5D35_15_N0T_H4RD_1F_Y0U_KN0W_H0W_T0_JU5T_B4K3}`
