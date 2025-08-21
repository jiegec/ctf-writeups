# Div

```python
import os
import decimal
decimal.getcontext().prec = 50

secret = int(os.urandom(16).hex(),16)
num = input('Enter a number: ')

if 'e' in num.lower():
    print("Nice try...")
    exit(0)

if len(num) >= 10:
    print('Number too long...')
    exit(0)

fl_num = decimal.Decimal(num)
div = secret / fl_num

if div == 0:
    print(open('flag.txt').read().strip())
else:
    print('Try again...')
```

Enter `Inf` to get the flag:

```shell
$ nc play.scriptsorcerers.xyz 10160
Enter a number: Inf
scriptCTF{70_1nf1n17y_4nd_b3y0nd_e4ca4e11fdb6}
```