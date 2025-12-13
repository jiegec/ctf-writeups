# HuntMe1

```
The hunt begins at night. You follow a quiet trail through the forest, guided only by instinct and patience. Nothing reacts. Nothing responds. Yet something is there.

Author : N!L
```

Writeup written by AI agent:

# HuntMe1 CTF Challenge Solution

## Challenge Analysis
The challenge is a 64-bit ELF binary named `HuntMe1`. When executed, it performs various checks and either:
- Prints "The forest feels wrong tonight..." and exits with code 1 (failure)
- Prints a series of poetic messages and exits with code 0 (success)

## Solution
The flag is embedded as a plain text string in the binary's .rodata section at address 0x2020. It can be extracted using:
- `strings HuntMe1 | grep nexus`
- `hexdump -C HuntMe1 | grep -i nexus`
- Any reverse engineering tool (IDA, Ghidra, etc.)

Flag: `nexus{h1dd3n_1n_7h3_f0r357_4t_n1gh7}`

## Binary Logic (Misdirection)
The binary contains obfuscated logic with:
- `setjmp`/`longjmp` for error handling
- Signal handlers for SIGSEGV (11) and SIGILL (4)
- Random number validation (`validate_environment()` returns `rand() % 2`)
- Complex state tracking functions (`track_shadows`, `meaningless_check`)
- Global state manipulation with checks for `0xBEEF` pattern

However, none of this logic reveals or uses the flag. The flag string is statically embedded and labeled as `hidden_payload` in the symbol table.

## Extraction Methods
1. **Simple strings extraction**: `strings HuntMe1`
2. **Hex dump**: `hexdump -C HuntMe1 | less`
3. **Reverse engineering**: Open in IDA/Ghidra to see string at 0x2020

This is a beginner-level challenge focusing on basic reverse engineering skills - recognizing that flags are often embedded as plain text strings in binaries.
