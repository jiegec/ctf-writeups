# ExecLLM

```
Did you know that the Apollo Guidance Computer used to land on the moon only had clock frequency of 2.048 MHz and about 4kb of RAM? In a similar vein of resource constraints, did you know you can implement machine learning models using Excel if you try hard enough? Our flag checker model is trained specifically to recognize the correct flag. Give it a shot!
```

Open the attachment, the excel computes a two level neural network for each input character.

Step 1: break input into bits in hidden sheet `BITS`:

```
=MOD(@com.sun.star.sheet.addin.Analysis.getQuotient(IFERROR(CODE(MID(LLM!B2,1,1)),0),2^7),2)
```

Step 2: multiple with coefficients in hidden sheet `WEIGHTS` for the first level:

```
=MAX(0,(SUMPRODUCT(BITS!B2:B9,WEIGHTS!A2:A9)+WEIGHTS!A10)/100)
```

Step 3: multiple with coefficients in hidden sheet `WEIGHTS` for the second level:

```
=--((SUMPRODUCT(C10:C17,WEIGHTS!A18:A25)+WEIGHTS!A26)/100>0)
```

Step 4: all outputs from the step 3 should be one to add up to 27:

```
=--(SUM(H10,H30,H50,H70,H90,H110,H130,H150,H170,H190,H210,H230,H250,H270,H290,H310,H330,H350,H370,H390,H410,H430,H450,H470,H490,H510,H530)=27)
```

Export the `WEIGHT` sheet to csv and remove the UTF-8 BOM. Bruteforce each byte to find flag:

```python
import csv

rows = list(csv.reader(open("ExceLLM.csv", "r")))
for i in range(0, len(rows), 26):

    # enumerate each byte
    for byte in range(32, 128):
        bits = [int(bit) for bit in bin(byte)[2:].zfill(8)]

        # step 1: dot product with each column
        prods = []
        for col in range(8):
            prod = sum(
                [
                    bit * int(coef)
                    for bit, coef in zip(bits, [rows[i + j][col] for j in range(8)])
                ]
            )
            prod = prod + int(rows[i + 8 + col][0])
            prod = prod / 100
            prod = max(prod, 0)
            prods.append(prod)

        # step 2. dot product with bias
        prod = sum(
            value * int(coef)
            for value, coef in zip(prods, [rows[i + 16 + j][0] for j in range(8)])
        )
        prod += int(rows[i + 24][0])
        if prod <= 0:
            continue
        else:
            # found
            print(chr(byte), end="")
```

Flag: `sun{n0t_qu1t3_ch4t_GPT_l0l}`.
