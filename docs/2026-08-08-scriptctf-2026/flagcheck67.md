# flagcheck67

```
i heard my lil bro's password was [READACTED]. just connect to the server and enter it for me, would u?

Note: Please test your solve locally before going on the remote! It has a Proof-of-Work (POW). Solver given in second attachment
Attachments

    check.py
    pow-solver.py

```

Attachment:

```python
import random, time
inp = input().strip()
assert all([(x in "67") for x in list(inp)])
num = float(inp)  
print('wrong' if num < 67676767 or 676767676767676767%(6767676767676767676767676767/num) == 676767.67 or random.randint(676767676767, 6767676767676767676)%num or num > 6767676767676767 or num//676767*676767==num or pow(67,67)//67676767676767==num or num+676767==67676767676767 else 'scriptCTF{fakeflag6767}')
```

The conditions are hard to satisfy. However, we can trigger an exception when num is very large. Then, the source code is printed with flag:

```shell
$ nc challs.scriptsorcerers.xyz 10243
sha256(rULb3yLmvPz6b1Vu + ???) == 0000000000000000000000(22 leading zero bits)...
???: 6132529
Proof-of-work correct! Continuing to the challenge...

666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666
Traceback (most recent call last):
  File "/app/main.py", line 31, in <module>
    print('wrong' if num < 67676767 or 676767676767676767%(6767676767676767676767676767/num) == 676767.67 or random.randint(676767676767, 6767676767676767676)%num or num > 6767676767676767 or num//676767*676767==num or pow(67,67)//67676767676767==num or num+676767==67676767676767 else 'scriptCTF{ch47_g3n_4lph4_15_50_c00k3d}')
                                       ~~~~~~~~~~~~~~~~~~^^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ZeroDivisionError: float modulo
```
