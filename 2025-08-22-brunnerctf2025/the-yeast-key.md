# The Yeast Key

```
Difficulty: Easy
Author: H4N5

Many years ago, the legendary baker Lionel Poilâne entrusted us with his original sourdough recipe. It's been locked away in the Vault ever since.

Only Poilâne knew the passphrase, and now he's gone. The only clue left behind? A strand of synthetic DNA extracted from his prized baker's yeast.

Can you decode the DNA and recover the vault key? The DNA is:

CGAGCTAGCTCCCGTGCGTGCGCCCTAGCTGTATACCGGCATAACGTGATATCGTACCTTCTAAATAACGGCATACATCACGTGATATCCTTCGTCATCAATCCATCTATATCTAGCCTTATAACGCGCCTTATCCATAACTCCCTAGCGCAATAACTCCATCGCGGACCTTCTAAATCAATCCATCCCTAACGGACTAGATCAATCCATATCCTTATACATCCCCTTCGATCTAGATAAATACATCCATCCATCACGTGATCTCCCGATCACTCCATACATCTAGACATGCATATCTTC
```

Convert `ACGT` to binary for each character. The exact mapping need to be brute-forced.

```python
c = "CGAGCTAGCTCCCGTGCGTGCGCCCTAGCTGTATACCGGCATAACGTGATATCGTACCTTCTAAATAACGGCATACATCACGTGATATCCTTCGTCATCAATCCATCTATATCTAGCCTTATAACGCGCCTTATCCATAACTCCCTAGCGCAATAACTCCATCGCGGACCTTCTAAATCAATCCATCCCTAACGGACTAGATCAATCCATATCCTTATACATCCCCTTCGATCTAGATAAATACATCCATCCATCACGTGATCTCCCGATCACTCCATACATCTAGACATGCATATCTTC"
alphabet = "ACGT"
data = []
for ch in c:
    index = alphabet.index(ch)
    data += bin(index)[2:].zfill(2)
s = "".join(data)
# https://stackoverflow.com/questions/32675679/convert-binary-string-to-bytearray-in-python-3
print(bytes(int(s[i : i + 8], 2) for i in range(0, len(s), 8)))
```

Get flag: `brunner{1i0n3l_p0i14n3_m4573r_0f_50urd0u6h_p455phr453_15_cr01554n7V4u17!93}`
