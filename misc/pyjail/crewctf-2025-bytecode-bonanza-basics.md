# CrewCTF 2025 Bytecode Bonanza - Basics

```python3
Python bytecode has many different opcodes, but how many opcodes do you really need? This challenge will teach you some of the concepts you need to tackle the RSA challenge.

ncat --ssl bytecode-bonanza-basics.chal.crewc.tf 1337

author : Aali
```

Attachment:

```python
import sys
import signal

assert((sys.version_info.major, sys.version_info.minor) == (3, 9))

signal.alarm(30)

FLAG = "crew{test flag please ignore}"

def dummy1(a):
  pass
def dummy2(a, b):
  pass
def dummy3(a, b, c):
  pass

dummies = [None, dummy1, dummy2, dummy3]

def create_function(parameters, prompt):
  bytecode = bytes.fromhex(input(prompt))
  
  if len(bytecode) > 512:
    print("Too long")
    exit()
  
  opcodes = [bytecode[i*2] + bytecode[i*2+1]*256 for i in range((len(bytecode)+1) // 2)]
  
  allowlist = [ 0x0001, 0x0004, 0x0006, 0x000f, 0x0017, 0x0190 ] + [0x0073 + i * 512 for i in range(128)]
  
  if any([op not in allowlist for op in opcodes]):
    print("Illegal opcode")
    exit()
  
  preamble = b"".join([bytes([0x7c, i]) for i in range(parameters)])
  
  code = preamble + bytecode + bytes([0x53, 0])
  
  dummy = dummies[parameters]
  
  dummy.__code__ = dummy.__code__.replace(co_code=code,co_stacksize=1000000000)
  
  return dummy

import secrets

subtract = create_function(2, "Enter a function which subtracts two numbers: ")

for i in range(10000):
  a = secrets.randbelow(2**32)
  b = secrets.randbelow(2**32)
  
  if subtract(a, b) != a - b:
    print("Nope")
    exit()

constant1337 = create_function(1, "Enter a function which always returns 1337: ")

for i in range(10000):
  if constant1337(secrets.randbelow(2**32)) != 1337:
    print("Nope")
    exit()

multiply = create_function(2, "Enter a function which multiplies two positive integers: ")

for i in range(10000):
  a = secrets.randbelow(255) + 1
  b = secrets.randbelow(255) + 1
  
  if multiply(a, b) != a * b:
    print(multiply(1, 3), 1, 3)
    print("Nope")
    exit()

print(FLAG)
```

Requirement:

1. Limit to the following opcodes in Python 3.9:
    1. POP_TOP: pop top element
    2. DUP_TOP: duplicate top element
    3. UNARY_INVERT: invert top element
    4. BINARY_ADD: pop two elements, push the sum of them
    5. POP_JUMP_IF_TRUE: pop top element, jump to target if element is true (non-zero)
    6. EXTENDED_ARG: construct 16 bit argument for the next op
2. Implement three functions: `a-b`, `1337` and `a*b`

To implement `a-b`, we can:

```
a - b
= a + (~b + 1)
= a + ~b + 1
= a + ~b + ~(-2)
= a + ~b + ~(-1 + -1)
= a + ~b + ~((b + ~b) + (b + ~b))
```

The corresponding opcodes:

```python
# def sub(a, b):
#     return a - b
# a - b = a + ~b + 1
code = bytes.fromhex(
    (
        # a b
        "0f00"  # UNARY_INVERT, a ~b
        + "0400"  # DUP_TOP, a ~b ~b
        + "0400"  # DUP_TOP, a ~b ~b ~b
        + "0f00"  # UNARY_INVERT, a ~b ~b b
        + "1700"  # BINARY_ADD, a ~b -1
        + "0400"  # DUP_TOP, a ~b -1 -1
        + "1700"  # BINARY_ADD, a ~b -2
        + "0f00"  # UNARY_INVERT, a ~b 1
        + "1700"  # BINARY_ADD, a ~b+1
        + "1700"  # BINARY_ADD, a+~b+1
    )
)
```

To compute `1337`, we can:

```
1337
= 1 + 8 + 16 + 32 + 256 + 1024
= 1 + 8 + 16 + 32 + 256 + (512 + 512)
= 1 + 8 + 16 + 32 + 256 + ((256 + 256) + (256 + 256))
= ...
```

We compute powers of two, while leaving intermediate values in stack until the final summation. The corresponding opcodes:

```python
# def const1337(a):
#     return 1337
# 1337 = 1 + 8 + 16 + 32 + 256 + 1024
code = bytes.fromhex(
    (
        # a
        "0400"  # DUP_TOP, a a
        + "0f00"  # UNARY_INVERT, a ~a
        + "1700"  # BINARY_ADD, -1
        + "0400"  # DUP_TOP, -1 -1
        + "1700"  # BINARY_ADD, -2
        + "0f00"  # UNARY_INVERT, 1
        + "0400"  # DUP_TOP, 1 1
        + "0400"  # DUP_TOP, 1 1 1
        + "1700"  # BINARY_ADD, 1 2
        + "0400"  # DUP_TOP, 1 2 2
        + "1700"  # BINARY_ADD, 1 4
        + "0400"  # DUP_TOP, 1 4 4
        + "1700"  # BINARY_ADD, 1 8
        + "0400"  # DUP_TOP, 1 8 8
        + "0400"  # DUP_TOP, 1 8 8 8
        + "1700"  # BINARY_ADD, 1 8 16
        + "0400"  # DUP_TOP, 1 8 16 16
        + "0400"  # DUP_TOP, 1 8 16 16 16
        + "1700"  # BINARY_ADD, 1 8 16 32
        + "0400"  # DUP_TOP, 1 8 16 32 32
        + "0400"  # DUP_TOP, 1 8 16 32 32 32
        + "1700"  # BINARY_ADD, 1 8 16 32 64
        + "0400"  # DUP_TOP, 1 8 16 32 64 64
        + "1700"  # BINARY_ADD, 1 8 16 32 128
        + "0400"  # DUP_TOP, 1 8 16 32 128 128
        + "1700"  # BINARY_ADD, 1 8 16 32 256
        + "0400"  # DUP_TOP, 1 8 16 32 256 256
        + "0400"  # DUP_TOP, 1 8 16 32 256 256 256
        + "1700"  # BINARY_ADD, 1 8 16 32 256 512
        + "0400"  # DUP_TOP, 1 8 16 32 256 512 512
        + "1700"  # BINARY_ADD, 1 8 16 32 256 1024
        + "1700"  # BINARY_ADD, 1 8 16 32 1280
        + "1700"  # BINARY_ADD, 1 8 16 1312
        + "1700"  # BINARY_ADD, 1 8 1328
        + "1700"  # BINARY_ADD, 1 1336
        + "1700"  # BINARY_ADD, 1337
    )
)
```

To compute `a*b`, we can:

```
a * b
= a * (b - 1) + a
= a * (b - 2) + a + 1
```

We use a loop to implement this: starting with four numbers, `a b -1 c` where c is the accumulator, compute `a b-1 -1 c+a` for the next iteration. When `b-1 == 0`, ends loop. Beware that the bytecode starts from 0x04 due to loading argument to stack added by the server. Opcodes:

```python
# def mul(a, b):
#     return a * b
code = bytes.fromhex(
    (
        # a b
        "0400"  # DUP_TOP, a b b
        + "0f00"  # UNARY_INVERT, a b ~b
        + "0400"  # DUP_TOP, a b ~b ~b
        + "0f00"  # UNARY_INVERT, a b ~b b
        + "1700"  # BINARY_ADD, a b -1
        + "0400"  # DUP_TOP, a b -1 -1
        + "0f00"  # UNARY_INVERT, a b -1 0
        # loop begin, from a b -1 c -> a b-1 -1 c+a
        + "0600"  # ROT_FOUR, c a b -1
        + "0600"  # ROT_FOUR, -1 c a b
        + "0600"  # ROT_FOUR, b -1 c a
        + "0400"  # DUP_TOP, b -1 c a a
        + "0600"  # ROT_FOUR, b a -1 c a
        + "1700"  # BINARY_ADD, b a -1 c+a
        + "0600"  # ROT_FOUR, c+a b a -1
        + "0400"  # DUP_TOP, c+a b a -1 -1
        + "0600"  # ROT_FOUR, c+a -1 b a -1
        + "0600"  # ROT_FOUR, c+a -1 -1 b a
        + "0600"  # ROT_FOUR, c+a a -1 -1 b
        + "1700"  # BINARY_ADD, c+a a -1 b-1
        + "0600"  # ROT_FOUR, b-1 c+a a -1
        + "0600"  # ROT_FOUR, -1 b-1 c+a a
        + "0600"  # ROT_FOUR, a -1 b-1 c+a
        + "0400"  # DUP_TOP, a -1 b-1 c+a c+a
        + "0600"  # ROT_FOUR, a c+a -1 b-1 c+a
        + "0100"  # POP_TOP, a c+a -1 b-1
        + "0400"  # DUP_TOP, a c+a -1 b-1 b-1
        + "0600"  # ROT_FOUR, a b-1 c+a -1 b-1
        + "0600"  # ROT_FOUR, a b-1 b-1 c+a -1
        + "0400"  # DUP_TOP, a b-1 b-1 c+a -1 -1
        + "0400"  # DUP_TOP, a b-1 b-1 c+a -1 -1 -1
        + "0600"  # ROT_FOUR, a b-1 b-1 -1 c+a -1 -1
        + "0100"  # POP_TOP, a b-1 b-1 -1 c+a -1
        + "0600"  # ROT_FOUR, a b-1 -1 b-1 -1 c+a
        + "0400"  # DUP_TOP, a b-1 -1 b-1 -1 c+a c+a
        + "0600"  # ROT_FOUR, a b-1 -1 c+a b-1 -1 c+a
        + "0100"  # POP_TOP, a b-1 -1 c+a b-1 -1
        + "0100"  # POP_TOP, a b-1 -1 c+a b-1
        + "7312"  # POP_JUMP_IF_TRUE to 0x0e(with offset 0x04, 0x0e+0x04=0x12), a b-1 -1 c+a
        + "0600"  # ROT_FOUR, c+a a b-1 -1
        + "0100"  # POP_TOP, c+a a b-1
        + "0100"  # POP_TOP, c+a a
        + "0100"  # POP_TOP, c+a
    )
)
```

To aid testing, a simple bytecode interpreter is written. The full attack script:

```python
from pwn import *
import dis

context(log_level="debug")

# p = process(["python3.9", "basics.py"])
p = process("ncat --ssl bytecode-bonanza-basics.chal.crewc.tf 1337".split())


for i, name in enumerate(dis.opname):
    if (
        i == 0x01  # POP_TOP
        or i == 0x04  # DUP_TOP
        or i == 0x06  # ROT_FOUR
        or i == 0x0F  # UNARY_INVERT
        or i == 0x17  # BINARY_ADD
        or i == 0x73  # POP_JUMP_IF_TRUE
        or i == 0x90  # EXTENDED_ARG
    ):
        print(hex(i), name)

# def sub(a, b):
#     return a - b
# a - b = a + ~b + 1
code = bytes.fromhex(
    (
        # a b
        "0f00"  # UNARY_INVERT, a ~b
        + "0400"  # DUP_TOP, a ~b ~b
        + "0400"  # DUP_TOP, a ~b ~b ~b
        + "0f00"  # UNARY_INVERT, a ~b ~b b
        + "1700"  # BINARY_ADD, a ~b -1
        + "0400"  # DUP_TOP, a ~b -1 -1
        + "1700"  # BINARY_ADD, a ~b -2
        + "0f00"  # UNARY_INVERT, a ~b 1
        + "1700"  # BINARY_ADD, a ~b+1
        + "1700"  # BINARY_ADD, a+~b+1
    )
)

print(code.hex())
print(dis.dis(code))
p.sendline(code.hex().encode())

# def const1337(a):
#     return 1337
# 1337 = 1 + 8 + 16 + 32 + 256 + 1024
code = bytes.fromhex(
    (
        # a
        "0400"  # DUP_TOP, a a
        + "0f00"  # UNARY_INVERT, a ~a
        + "1700"  # BINARY_ADD, -1
        + "0400"  # DUP_TOP, -1 -1
        + "1700"  # BINARY_ADD, -2
        + "0f00"  # UNARY_INVERT, 1
        + "0400"  # DUP_TOP, 1 1
        + "0400"  # DUP_TOP, 1 1 1
        + "1700"  # BINARY_ADD, 1 2
        + "0400"  # DUP_TOP, 1 2 2
        + "1700"  # BINARY_ADD, 1 4
        + "0400"  # DUP_TOP, 1 4 4
        + "1700"  # BINARY_ADD, 1 8
        + "0400"  # DUP_TOP, 1 8 8
        + "0400"  # DUP_TOP, 1 8 8 8
        + "1700"  # BINARY_ADD, 1 8 16
        + "0400"  # DUP_TOP, 1 8 16 16
        + "0400"  # DUP_TOP, 1 8 16 16 16
        + "1700"  # BINARY_ADD, 1 8 16 32
        + "0400"  # DUP_TOP, 1 8 16 32 32
        + "0400"  # DUP_TOP, 1 8 16 32 32 32
        + "1700"  # BINARY_ADD, 1 8 16 32 64
        + "0400"  # DUP_TOP, 1 8 16 32 64 64
        + "1700"  # BINARY_ADD, 1 8 16 32 128
        + "0400"  # DUP_TOP, 1 8 16 32 128 128
        + "1700"  # BINARY_ADD, 1 8 16 32 256
        + "0400"  # DUP_TOP, 1 8 16 32 256 256
        + "0400"  # DUP_TOP, 1 8 16 32 256 256 256
        + "1700"  # BINARY_ADD, 1 8 16 32 256 512
        + "0400"  # DUP_TOP, 1 8 16 32 256 512 512
        + "1700"  # BINARY_ADD, 1 8 16 32 256 1024
        + "1700"  # BINARY_ADD, 1 8 16 32 1280
        + "1700"  # BINARY_ADD, 1 8 16 1312
        + "1700"  # BINARY_ADD, 1 8 1328
        + "1700"  # BINARY_ADD, 1 1336
        + "1700"  # BINARY_ADD, 1337
    )
)

print(code.hex())
print(dis.dis(code))
p.sendline(code.hex().encode())

# def mul(a, b):
#     return a * b
code = bytes.fromhex(
    (
        # a b
        "0400"  # DUP_TOP, a b b
        + "0f00"  # UNARY_INVERT, a b ~b
        + "0400"  # DUP_TOP, a b ~b ~b
        + "0f00"  # UNARY_INVERT, a b ~b b
        + "1700"  # BINARY_ADD, a b -1
        + "0400"  # DUP_TOP, a b -1 -1
        + "0f00"  # UNARY_INVERT, a b -1 0
        # loop begin, from a b -1 c -> a b-1 -1 c+a
        + "0600"  # ROT_FOUR, c a b -1
        + "0600"  # ROT_FOUR, -1 c a b
        + "0600"  # ROT_FOUR, b -1 c a
        + "0400"  # DUP_TOP, b -1 c a a
        + "0600"  # ROT_FOUR, b a -1 c a
        + "1700"  # BINARY_ADD, b a -1 c+a
        + "0600"  # ROT_FOUR, c+a b a -1
        + "0400"  # DUP_TOP, c+a b a -1 -1
        + "0600"  # ROT_FOUR, c+a -1 b a -1
        + "0600"  # ROT_FOUR, c+a -1 -1 b a
        + "0600"  # ROT_FOUR, c+a a -1 -1 b
        + "1700"  # BINARY_ADD, c+a a -1 b-1
        + "0600"  # ROT_FOUR, b-1 c+a a -1
        + "0600"  # ROT_FOUR, -1 b-1 c+a a
        + "0600"  # ROT_FOUR, a -1 b-1 c+a
        + "0400"  # DUP_TOP, a -1 b-1 c+a c+a
        + "0600"  # ROT_FOUR, a c+a -1 b-1 c+a
        + "0100"  # POP_TOP, a c+a -1 b-1
        + "0400"  # DUP_TOP, a c+a -1 b-1 b-1
        + "0600"  # ROT_FOUR, a b-1 c+a -1 b-1
        + "0600"  # ROT_FOUR, a b-1 b-1 c+a -1
        + "0400"  # DUP_TOP, a b-1 b-1 c+a -1 -1
        + "0400"  # DUP_TOP, a b-1 b-1 c+a -1 -1 -1
        + "0600"  # ROT_FOUR, a b-1 b-1 -1 c+a -1 -1
        + "0100"  # POP_TOP, a b-1 b-1 -1 c+a -1
        + "0600"  # ROT_FOUR, a b-1 -1 b-1 -1 c+a
        + "0400"  # DUP_TOP, a b-1 -1 b-1 -1 c+a c+a
        + "0600"  # ROT_FOUR, a b-1 -1 c+a b-1 -1 c+a
        + "0100"  # POP_TOP, a b-1 -1 c+a b-1 -1
        + "0100"  # POP_TOP, a b-1 -1 c+a b-1
        + "7312"  # POP_JUMP_IF_TRUE to 0x0e(with offset 0x04, 0x0e+0x04=0x12), a b-1 -1 c+a
        + "0600"  # ROT_FOUR, c+a a b-1 -1
        + "0100"  # POP_TOP, c+a a b-1
        + "0100"  # POP_TOP, c+a a
        + "0100"  # POP_TOP, c+a
    )
)


print(code.hex())
print(dis.dis(code))
p.sendline(code.hex().encode())

p.interactive()


# simulate bytecode interpreter for testing
def simulate(a, b):
    stack = [a, b]
    i = 0
    while i < len(code):
        print(i, stack)
        cur = code[i]
        if cur == 0x01:  # POP_TOP
            stack.pop()
        elif cur == 0x04:  # DUP_TOP
            stack.append(stack[-1])
        elif cur == 0x06:  # ROT_FOUR
            a = stack.pop()
            b = stack.pop()
            c = stack.pop()
            d = stack.pop()
            stack.append(a)
            stack.append(d)
            stack.append(c)
            stack.append(b)
        elif cur == 0x0F:  # UNARY_INVERT
            stack[-1] = ~stack[-1]
        elif cur == 0x17:  # BINARY_ADD
            a = stack.pop()
            b = stack.pop()
            stack.append(a + b)
        elif cur == 0x73:  # POP_JUMP_IF_TRUE
            a = stack.pop()
            if a > 0:
                i = code[i + 1] - 0x04  # we don't have preamble
                continue
        else:
            assert False
        i += 2
    print(stack)
```

Flag: `crew{Ready_to_take_on_the_RSA_challenge?_e119c5d7}`.
