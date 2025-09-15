# Python jail

References:

- [Pyjail Cheatsheet](https://shirajuki.js.org/blog/pyjail-cheatsheet/)

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

## TCP1P CTF 2023 PyMagic

Requirements:

1. No `()`: Use `class.__class_getitem__` and `class[]` to bypass
2. No strings: Use docstrings and `str[index]` to create strings
3. No numbers: Use `True` as 1
4. No spaces: Use `\r` to bypass while making `input()` happy
5. No builtins: Use `().__class__.__base__.__subclasses__()`

Details [here](./pyjail/tcp1p-ctf-2023-pymagic.md).

## ImaginaryCTF 2024 ok_nice

Requirements:

1. No numbers: Use `True` as 1
2. Exception side channel: Use integer division by zero to guess each character
3. `len(set(input)) <= 17`: Reuse characters already appeared

Details [here](./pyjail/imaginaryctf-2024-ok-nice.md).

# NTUA_H4CK 2024 Snekbox

Requirements:

1. No non-ascii characters
2. Blacklisted dangerous functions: Use `globals()[function_name]` to bypass

Details [here](./pyjail/ntua-h4ck-2024-snekbox.md).

# ImaginaryCTF 2024 calc

Requirements:

1. Input is a expression: Use list comprehension to execute multiple statements
2. Input should match regex: Use `1,` to bypass since it is not a full match
3. Audit hook: Add signal handler, raise signal and change content of the audit hook to bypass

Details [here](./pyjail/imaginaryctf-2024-calc.md).
