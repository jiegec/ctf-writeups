# TheBakingCase

```
Misc Steganography

Difficulty: Beginner
Author: H4N5

I hid a message for you here, see if you can find it! Take it slow, little by little, bit by bit.

i UseD to coDE liKe A sLEEp-dEprIVed SqUirRel smasHInG keYs HOPinG BugS would dISApPear THrOugh fEAr tHeN i sPilled cOFfeE On mY LaPTop sCReameD iNTerNALly And bakeD BanaNa bREAd oUt oF PAnIc TuRNs OUT doUGh IS EasIEr tO dEbUG ThaN jaVASCrIPt Now I whIsPeR SWEEt NOtHIngs TO sOurDoUGh StARtERs aNd ThReATEN CrOissaNts IF they DoN'T rIsE My OVeN haS fEWeR CRasHEs tHAN mY oLD DEV sErvER aNd WHeN THInGS BurN i jUSt cAlL iT cARAMElIzEd FeatUReS no moRE meetInGS ThAt coUlD HAVE bEeN emailS JUst MufFInS THAt COulD HAvE BEen CupCAkes i OnCE tRIeD tO GiT PuSh MY cInnAmON rOLLs aND paNICkED WHEn I coUldn't reVErt ThEm NOw i liVe IN PeaCE uNLESs tHe yEast getS IDeas abOVe iTs StATion oR a COOkiE TrIES To sEgfAult my toOTH FILlings
```

The upper/lower case of letters encodes a binary string containing the flag:

```python
text = "i UseD to coDE liKe A sLEEp-dEprIVed SqUirRel smasHInG keYs HOPinG BugS would dISApPear THrOugh fEAr tHeN i sPilled cOFfeE On mY LaPTop sCReameD iNTerNALly And bakeD BanaNa bREAd oUt oF PAnIc TuRNs OUT doUGh IS EasIEr tO dEbUG ThaN jaVASCrIPt Now I whIsPeR SWEEt NOtHIngs TO sOurDoUGh StARtERs aNd ThReATEN CrOissaNts IF they DoN'T rIsE My OVeN haS fEWeR CRasHEs tHAN mY oLD DEV sErvER aNd WHeN THInGS BurN i jUSt cAlL iT cARAMElIzEd FeatUReS no moRE meetInGS ThAt coUlD HAVE bEeN emailS JUst MufFInS THAt COulD HAvE BEen CupCAkes i OnCE tRIeD tO GiT PuSh MY cInnAmON rOLLs aND paNICkED WHEn I coUldn't reVErt ThEm NOw i liVe IN PeaCE uNLESs tHe yEast getS IDeas abOVe iTs StATion oR a COOkiE TrIES To sEgfAult my toOTH FILlings"
bits = []
for char in text:
    if char >= "a" and char <= "z":
        bits.append(0)
    elif char >= "A" and char <= "Z":
        bits.append(1)
bits += [0, 0, 0] # padding
data = []
for i in range(0, len(bits), 8):
    data.append((bits[i] << 7) | (bits[i+1] << 6) | (bits[i+2] << 5) | (bits[i+3] << 4) | (bits[i+4] << 3) | (bits[i+5] << 2) | (bits[i+6] << 1) |(bits[i+7] << 0))
print(bytes(data))
```

Get flag: `b'Here is the flag brunner{I_like_Baking_More_That_Programming} easy peasy ?\x00'`
