# Python jail

References:

- [Pyjail Cheatsheet](https://shirajuki.js.org/blog/pyjail-cheatsheet/)
- [pyjail collection](https://github.com/jailctf/pyjail-collection)

Table of contents:

* TOC
{:toc}

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

## UIUCTF 2024 Astea

Requirements:

1. No function call: Use `f"{license}" for license._Printer__setup in [function_to_call]]` to call `function_to_call`
2. No builtins: Use `.__builtins__` of the given function to access builtins dict, or `.__globals__["__builtins__"]` of the given function to access builtins module
3. No assignment: Use `[a:=b]` for assignment

Details [here](./pyjail/uiuctf-2024-astea.md).

## UofTCTF 2024 Jail Zero

Requirements:

1. No alphabetic: Use [Unicode Block “Mathematical Alphanumeric Symbols”](https://www.compart.com/en/unicode/block/U+1D400) to bypass
2. No numbers: Use `(''=='')` as 1
3. No double underscores: Use [FULLWIDTH LOW LINE](https://unicode-explorer.com/c/FF3F)
4. No builtins: Use `().__class__.__base__.__subclasses__()`

Details [here](./pyjail/uoftctf-2024-jail-zero.md).

## SECCON 2024 Quals 1linepyjail

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

## NTUA_H4CK 2024 Snekbox

Requirements:

1. No non-ascii characters
2. Blacklisted dangerous functions: Use `globals()[function_name]` to bypass

Details [here](./pyjail/ntua-h4ck-2024-snekbox.md).

## ImaginaryCTF 2024 calc

Requirements:

1. Input is a expression: Use list comprehension to execute multiple statements
2. Input should match regex: Use `1,` to bypass since it is not a full match
3. Audit hook: Add signal handler, raise signal and change content of the audit hook to bypass

Details [here](./pyjail/imaginaryctf-2024-calc.md).

## TBTL CTF 2024 Squeezing Tightly On Arm

Requirements:

1. No `'`: Use `"` for strings
2. Some characters may appear only once: save intermediate values to locals
3. No builtins: Use `().__class__.__base__.__subclasses__()` to bypass

Details [here](./pyjail/tbtl-ctf-2024-squeezing-tightly-on-arm.md).

## TCP1P CTF 2024 typically not a revenge

Requirements:

1. No numbers: Use `arr[[]is[]]` for `arr[0]`, `arr[not[]is[]]` for `arr[1]`, `arr[not[]is[]:][not[]is[]]` for `arr[2]`
2. No parens: Use `[obj[arg] for obj.__class_getitem in [function_to_call]]` to call function
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
