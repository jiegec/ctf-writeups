# The Woven Lights of Langmere

```
Across the marshes of Langmere, signal lanterns once guided travelers home. Each sequence of blinks formed a code, weaving words out of flame. But on Samhain night, the lights faltered, and the messages split into many possible meanings.

Each sequence is given as a string of digits. A digit or a pair of digits may represent a letter:
1 through 26 map to A through Z.

The catch is that a zero cannot stand alone. It may only appear as part of 10 or 20.  
For example, the string 111 can be read three different ways: AAA, AK, or KA.

Your task is to determine how many distinct messages a lantern sequence might carry. Since the number of possible decodings can grow very large, you must return the result modulo 1000000007.

The input consists of a single line containing a string S of digits.  
The string will not contain leading zeros.

Output a single integer, the number of valid decodings of S modulo 1000000007.

5 ≤ |S| ≤ 20000
Note: a valid number will not have leading zeros.
Example:

Input:
111

Expected output:
3

There are three valid decodings of 111.  
111 → AAA (1 (A) | 1 (A) | 1 (A)) 
111 → AK  (1 (A) | 11 (K))
111 → KA  (11 (K) | 1 (A))

So the answer is 3.
```

Use dynamic programming: for each location in the sequence, we check if the last one or two digits may be mapped to a letter. If so, count the possiblities for the corresponding prefix.

Code:

```python
# take in the number
n = input()

# calculate answer
dp = []

for i in range(len(n)):
    if i == 0:
        if n[0] == '0':
            dp.append(0)
        else:
            dp.append(1)
    else:
        # one letter
        if n[i] != '0':
            res = dp[-1]
        else:
            res = 0
        # last two letters okay?
        if int(n[i-1:i+1]) <= 26 and n[i-1] != '0':
            if i >= 2:
                res = res + dp[-2]
            else:
                res = res + 1
        dp.append(res % 1000000007)


# print answer
print(dp[-1])
```

Flag: `HTB{l4nt3rn_w0v3_mult1pl3_m34n1ngs}`.
