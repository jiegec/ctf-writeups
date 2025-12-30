# brainfudge

```
have you heard of pyfuck?

nc challs2.pyjail.club 21019
```

Attachment:

```python
#!/usr/local/bin/python3
from bfi import interpret

def bf_eval(code: str) -> str:
    return interpret(code, input_data='', buffer_output=True)

def py_eval(code: str) -> str:
    return str(eval(code))

code = input('> ')

if any(c not in '<>-+.,[]' for c in code):
    print('bf only pls')
    exit()

if bf_eval(code) == py_eval(code):
    print(open('flag.txt', 'r').read())
```

Not solved in competition. It requires us to create a string that evaluates to the same value in both Brainfuck and Python. In Brainfuck, output is only possible via `.`, however, we cannot create valid identifiers for `.` in Python, unless we use `...` which is the singleton of `Ellipsis`. Then the problem is, we must print three same characters in brainfuck everytime `...` is executed. No idea how to proceed.

Writeup by @flocto on Discord:

```python
t = ord('1')

payload = '+' * t
payload += '[...,'
payload += '-' * t
payload += '[[]<[]][[]<[]]'

t2 = 111
payload += ','
payload += '--++[[[]]>[]][[]<[]]' * t2

payload += ']' + '[[[[]]>[]][[]<[]]<<[[[]]>[]][[]<[]]]'

print(payload)
```

The idea is:

1. use `...` to print three duplicated characters in brainfuck, e.g. `111`
2. so the python code should evaluates to `111`
3. for brainfuck, print `111` in the very beginning, then balance `-` and `+` so that all `[]` constructs are skipped over
4. for python, use `...` early, but put it into an array: `[..., 0, 111]` so that we can drop its value later by `[..., 0, 111][2]`
5. to compute 111 with balanced `-` and `+`: `--++1--++1--++1`, where `a--b` is essentially `a+b`

Annotated attack script:

```python
from pwn import *

t = ord("1")

# B for brainfuck, P for python
# B: increment data to ascii value of `1`
# P: +111 is still 111, do nothing
payload = "+" * t
# B: print `1` three times, that's everything printed
# P: ellipsis, useless in python
payload += "[...,"
# B: decrement data to zero, so that all loops below are skipped
# P: []<[] is False, so essentially ---False, negating zero gives zero
payload += "-" * t
payload += "[[]<[]][[]<[]]"

t2 = 111
payload += ","
# B: keep data to zero, so that all loops below are skipped
# P: [[]]>[] is True, []<[] is False, so essentially --++True, which is one;
# adding all these ones (a--b is a+b) equals to 111
payload += "--++[[[]]>[]][[]<[]]" * t2

# P: the previous part evaluates to [Ellipsis, 0, 111]
# so the last thing is to get its third element
# [[[[]]>[]][[]<[]]<<[[[]]>[]][[]<[]]]
# == [[True][False]<<[True][False]]
# == [1<<1]
# == [2]
payload += "]" + "[[[[]]>[]][[]<[]]<<[[[]]>[]][[]<[]]]"

# finally
# "111" == "111"
print(payload)

p = process(["python3", "main.py"])
p.sendline(payload.encode())
p.interactive()
```

