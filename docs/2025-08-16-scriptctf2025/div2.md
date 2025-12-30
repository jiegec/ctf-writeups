# Div 2

Provided code:

```python
import secrets
import decimal
decimal.getcontext().prec = 50
secret =  secrets.randbelow(1 << 127) + (1 << 127) # Choose a 128 bit number
for _ in range(1000):
    print("[1] Provide a number\n[2] Guess the secret number")
    choice = int(input("Choice: "))
    if choice == 1:
        num = input('Enter a number: ')
        fl_num = decimal.Decimal(num)
        assert int(fl_num).bit_length() == secret.bit_length()
        div = secret / fl_num
        print(int(div))
    if choice == 2:
        guess = int(input("Enter secret number: "))
        if guess == secret:
            print(open('flag.txt').read().strip())
        else:
            print("Incorrect!")
        exit(0)
```

Use binary search to find secret:

```python
from pwn import *

context(log_level="debug")

p = remote("play.scriptsorcerers.xyz", 10076)
#p = process("./div2-chall.py")
left = 1 << 127
right = 1 << 128
while left + 1 < right:
    mid = (left + right) // 2
    p.sendline("1")
    p.recvuntil("number:")
    p.sendline(str(mid))
    res = int(p.recvline("number").strip())
    print(res)
    if res == 0:
        right = mid
    else:
        left = mid
    print(left, right)
p.sendline("2")
p.sendline(str(left))
p.interactive()
```

Get flag: `scriptCTF{b1n4ry_s34rch_u51ng_d1v1s10n?!!_6945c7e21098}`
