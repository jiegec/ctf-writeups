# shadow_spider_network

The attachment contains RC4 logic, but it is not actually used: When the input string overflows the buffer, the `__stack_chk_fail` is called, which is changed to some logic that triggers the signal handler, which actually checks the flag.

The rest is solved by AI.

Attack code:

```python
# decompilation of the signal handler
# e.g.
# if ( *(_WORD *)(a3[15] + 17LL) == 125 )
# else if ( *(_BYTE *)(a3[15] - 19LL) == 109 )
flag = bytearray(82)
for line in open("decompiled.txt", "r"):
    if "a3[15]" in line:
        if "LL" in line.split()[5]:
            sign = line.split()[4]
            offset = int(line.split()[5].removesuffix("LL)"))
        elif "LL" in line.split()[6]:
            sign = line.split()[5]
            offset = int(line.split()[6].removesuffix("LL)"))
        else:
            sign = "+"
            offset = 0
        value = int(line.split()[-2])
        if sign == "+":
            offset = -offset
        flag[64 - offset] = value
print(flag)
```

Analysis by AI:

# TSGCTF 2025 - Shadow Spider Network Writeup

**Category:** Reverse Engineering  
**Difficulty:** Hard  
**Author:** TSG  
**Flag:** `TSGCTF{Inv3571ga710n_1n70_BOF_Or13n73d_Pr0gramm1ng_a5_a_73chn1qu3_f0r_0bfu5ca710n}`

## Challenge Overview

We are given a binary that appears to implement RC4 encryption/decryption for flag verification. The binary prompts for a flag and checks it against what seems to be RC4-encrypted data. However, there's a contradiction: the code checks `strlen(input) == 40` but then compares 48 bytes against RC4-decrypted data.

## Initial Analysis

### Basic Reconnaissance
```bash
$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., for GNU/Linux 3.2.0, stripped

$ checksec chall
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

### Main Function Analysis
The main function is simple:
```c
void main() {
    printf("FLAG> ");
    if (verify_function()) {
        puts("Wrong");
    } else {
        puts("Correct!");
    }
    exit(0);
}
```

### Verification Function
The verification function `sub_40419F` appears to implement RC4:
1. Initializes S-box with 0-255
2. Uses a key from global variable `s` (37 bytes: "the_flying_cabbage_eats_purple_clocks")
3. Performs RC4 key scheduling
4. Checks `strlen(input) == 40`
5. Generates RC4 keystream and compares 48 bytes against encrypted data at `byte_4050A0`

**Contradiction:** The function checks for 40-character input but compares 48 bytes!

## Deep Dive: Signal Handler Obfuscation

### Signal Handler Discovery
Looking at initialization functions, we find `sub_403F4F` which sets up signal handlers:
```c
void setup_signals() {
    // Set up alternate signal stack
    struct sigaltstack s;
    memset(&s, 0, sizeof(s));
    s.ss_sp = malloc(sysconf(_SC_PAGESIZE));
    s.ss_size = sysconf(_SC_PAGESIZE);
    s.ss_flags = 0;
    sigaltstack(&s, 0);
    
    // Set up signal handler
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = (__sighandler_t)sub_401363;  // Signal handler
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_ONSTACK;  // Use alternate stack
    
    // Register for SIGSEGV (11) and SIGILL (4)
    sigaction(11, &act, 0);  // SIGSEGV
    sigaction(4, &act, 0);   // SIGILL
}
```

### Signal Handler Analysis
The signal handler `sub_401363` is complex (1455 lines of decompiled code). It implements a state machine that:
- Checks the current RIP (`a3[21]`) to determine state
- For each state, checks a specific byte at an offset from `a3[15]`
- If byte matches expected value, sets next RIP to continue
- If mismatch, sets RIP to crash function (`sub_401080`)

The handler has 82 unique character checks with offsets from -64 to +17.

## The Real Verification Mechanism

### Understanding the Signal Handler Checks
The signal handler checks take the form:
```c
if (*(_BYTE *)(a3[15] + offset) == expected_char)
```

Where:
- `a3[15]` is the faulting address (RIP in signal context)
- `offset` ranges from -64 to +17
- `expected_char` is an ASCII value

### The Buffer Overflow Trick
The verification function uses:
```c
_BYTE v1[56];  // 56-byte buffer
__isoc99_scanf("%s", v1);  // Unsafe - no length limit!
```

The program:
1. Reads input with `scanf("%s", v1)` which can overflow the 56-byte buffer
2. Intentionally causes faults at `input + 64`
3. Signal handler checks 82 bytes around the faulting address

### Mapping Offsets to Input
If the program faults at `input + 64`, then:
- `a3[15]` (RIP) = `input + 64`
- `input[0]` is at offset -64
- `input[1]` is at offset -63
- ...
- `input[81]` is at offset +17

Thus, the input needs to be 82 characters to satisfy all checks.

## Extracting the Flag

### Signal Handler Character Checks
By analyzing the signal handler, we extract all 82 (offset, char) pairs:

| Offset | Char | Decimal | Description   |
|--------|------|---------|---------------|
| -64    | T    | 84      | Start of flag |
| -63    | S    | 83      |               |
| -62    | G    | 71      |               |
| -61    | C    | 67      |               |
| -60    | T    | 84      |               |
| -59    | F    | 70      |               |
| -58    | {    | 123     | Flag opening  |
| -57    | I    | 73      |               |
| ...    | ...  | ...     | ...           |
| +17    | }    | 125     | Flag closing  |

### Reconstructing the Flag
We wrote a Python script to reconstruct the flag from the checks:
```python
# Map offsets to indices: index = offset + 64
checks = [
    (-64, 84, 'T'), (-63, 83, 'S'), (-62, 71, 'G'),
    (-61, 67, 'C'), (-60, 84, 'T'), (-59, 70, 'F'),
    (-58, 123, '{'), (-57, 73, 'I'), (-56, 110, 'n'),
    # ... all 82 checks ...
    (+17, 125, '}')
]

# Reconstruct
flag_chars = ['?'] * 82
for offset, decimal, char in checks:
    index = offset + 64
    flag_chars[index] = char

flag = ''.join(flag_chars)
```

### The Complete Flag
```
TSGCTF{Inv3571ga710n_1n70_BOF_Or13n73d_Pr0gramm1ng_a5_a_73chn1qu3_f0r_0bfu5ca710n}
```

**Translation (with leetspeak decoded):**  
"Investigation into BOF Oriented Programming as a technique for obfuscation"

## Solving the Contradiction

### How the 40 vs 48 Byte Issue is Resolved
1. **Normal execution path:** `strlen(input) == 40` check fails for 82-byte input
2. **Signal handler intervention:** The program intentionally causes signals
3. **Signal handler modifies execution:** Changes RIP or other registers to bypass the check
4. **State machine completion:** If all 82 checks pass, signal handler sets success state

### RC4's Actual Role
The RC4 verification at `loc_404486` is just **one state** in the larger signal handler state machine. It's not the primary verification mechanism but rather part of the obfuscation.

## Solution Script

```python
#!/usr/bin/env python3
import subprocess

flag = "TSGCTF{Inv3571ga710n_1n70_BOF_Or13n73d_Pr0gramm1ng_a5_a_73chn1qu3_f0r_0bfu5ca710n}"

# Run the binary
proc = subprocess.run(
    ["./chall"],
    input=flag + "\n",
    text=True,
    capture_output=True
)

print(proc.stdout)
# Output: FLAG> Correct!
```

## Key Takeaways

1. **Signal-based Control Flow:** The challenge uses signal handlers (SIGSEGV/SIGILL) for control flow obfuscation
2. **Buffer Overflow as Feature:** Intentional buffer overflow is part of the verification mechanism
3. **State Machine Verification:** Flag verification happens through a state machine in the signal handler
4. **Red Herrings:** RC4 and the 40-byte check are distractions from the real verification
5. **Context Awareness:** Understanding signal context (`ucontext_t`) is crucial for solving

## Tools Used
- Python for analysis and automation
- GDB for debugging (though patching was needed to bypass anti-debugging)
- Signal handler analysis tools

## Flag
`TSGCTF{Inv3571ga710n_1n70_BOF_Or13n73d_Pr0gramm1ng_a5_a_73chn1qu3_f0r_0bfu5ca710n}`

## References
- Linux `ucontext_t` structure and signal handling
- RC4 algorithm implementation
- Buffer overflow exploitation techniques
- Signal-based control flow obfuscation patterns