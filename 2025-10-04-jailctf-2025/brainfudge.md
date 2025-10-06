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

