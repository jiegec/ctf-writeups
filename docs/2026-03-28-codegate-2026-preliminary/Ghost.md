# Ghost

Co-authors: @Rosayxy

```
Someday I'll, I wanna wear a starry crown

nc 43.200.71.14 13479

nc 43.203.191.54 13479

nc 54.116.48.199 13479
```

Attachment:

```python
# server.py
#!/usr/bin/env python3

import secrets
from utils import dm_compress, hex_to_words, round_core
from secret import SBOXES, BANNER, FLAG

def main():
    iv = secrets.randbits(64)
    chances = 2**7

    print(BANNER)
    print(f"IV = {iv:016x}")
    print(f"Chances = {chances}/{2**7}")

    while True:
        print(
            "\n"
            "[1] query\n"
            "[2] submit\n"
            "[3] quit"
        )

        choice = input("> ")

        if choice == "1":
            if chances <= 0:
                print("Nope!\n")
                continue

            right_s = input("right > ")
            key_s = input("subkey > ")

            try:
                right = int(right_s, 16)
                subkey = int(key_s, 16)
            except:
                print("Bad input\n")
                continue

            chances -= 1
            y = round_core(right, subkey, SBOXES)

            print(f"core = {y:08x}")

        elif choice == "2":
            m1s = input("m1 > ")
            m2s = input("m2 > ")

            try:
                w1 = hex_to_words(m1s)
                w2 = hex_to_words(m2s)
            except Exception as e:
                continue

            if w1 == w2:
                print("Blocks must differ\n")
                continue

            h1 = dm_compress(iv, w1, SBOXES)
            h2 = dm_compress(iv, w2, SBOXES)

            if h1 == h2:
                print("Good!")
                print(f"flag = {FLAG()}\n")
            else:
                print("Nope!")

            return

        elif choice == "3":
            print("Bye!\n")
            return
        
        else:
            print("Only 1,2,3 are allowed\n")

if __name__ == "__main__":
    main()
# utils.py
MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

def dm_compress(iv, key_words, sboxes):
    return encrypt_block(iv, key_words, sboxes) ^ iv

def encrypt_block(block, key_words, sboxes):
    state = split_block(block)
    state = encrypt_rounds_from_state(state, full_schedule(key_words), sboxes)
    return join_block(*state)

def split_block(block):
    return ((block >> 32) & MASK32, block & MASK32)

def encrypt_rounds_from_state(state, round_keys, sboxes):
    cur = state
    for k in round_keys:
        cur = apply_round(cur, k, sboxes)
    return cur

def apply_round(state, subkey, sboxes):
    left, right = state
    return (right & MASK32, (left ^ round_core(right, subkey, sboxes)) & MASK32)

def round_core(right, subkey, sboxes):
    return rotl32(sbox_layer((right + subkey) & MASK32, sboxes), 11)

def rotl32(x, r):
    x &= MASK32
    return ((x << r) & MASK32) | (x >> (32 - r))

def sbox_layer(x, sboxes):
    y = 0
    for i in range(8):
        nib = (x >> (4 * i)) & 0xF
        y |= (sboxes[i][nib] & 0xF) << (4 * i)
    return y & MASK32

def full_schedule(key_words):
    if len(key_words) != 8:
        raise ValueError("expected 8 key words")
    return list(key_words) * 3 + list(reversed(key_words))

def hex_to_words(hex_string):
    s = hex_string.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) != 64 or any(c not in "0123456789abcdef" for c in s):
        raise ValueError("message block must be 64 hex chars")
    return [int(s[i : i + 8], 16) for i in range(0, 64, 8)]

def join_block(left, right):
    return ((left & MASK32) << 32) | (right & MASK32)
```

Idea by Claude:

1. We can recover S-box after 16 queries
2. With S-box, we can search for hash collisions
3. The search can be slow, use compiled C code to accelerate

Code:

```python
#!/usr/bin/env python3
"""
Collision attack on Davies-Meyer + custom Feistel cipher.

Attack:
1. Recover S-boxes (16 queries).
2. Compile optimized C solver with baked-in S-boxes.
3. Launch C solver, submit collision before 10s timeout.

Collision method: palindromic keys [a,b,c,d,d,c,b,a] make the key schedule
repeat 4x. If 8-round Feistel E has iv as a fixed point (E(iv)=iv), then
encrypt = E^4(iv) = iv, so dm_compress = iv ^ iv = 0. Two different fixed-point
keys => collision (both hash to 0).

Fixed-point MITM: split E into fwd 4 rounds (keys a,b,c,d) and bwd 4 rounds
(keys d,c,b,a). Fix (a,b), scan c, solve for d analytically via sbox_layer_inv,
check second equation.
"""

import os, sys, subprocess, time
from pwn import *

context(log_level="DEBUG")

MASK32 = 0xFFFFFFFF

def rotl32(x, r):
    x &= MASK32
    return ((x << r) & MASK32) | (x >> (32 - r))

def rotr32(x, r):
    return rotl32(x, 32 - r)

def sbox_layer(x, sboxes):
    y = 0
    for i in range(8):
        y |= (sboxes[i][(x >> (4*i)) & 0xF] & 0xF) << (4*i)
    return y & MASK32

def round_core(right, subkey, sboxes):
    return rotl32(sbox_layer((right + subkey) & MASK32, sboxes), 11)

def full_schedule(kw):
    return list(kw) * 3 + list(reversed(kw))

def encrypt_block(block, kw, sboxes):
    L, R = (block >> 32) & MASK32, block & MASK32
    for k in full_schedule(kw):
        L, R = R, (L ^ round_core(R, k, sboxes)) & MASK32
    return (L << 32) | R

def dm_compress(iv, kw, sboxes):
    return encrypt_block(iv, kw, sboxes) ^ iv

def words_to_hex(w):
    return ''.join(f'{x:08x}' for x in w)

def recover_sboxes(r):
    sboxes = [[0]*16 for _ in range(8)]
    for v in range(16):
        right_val = v * 0x11111111
        r.sendlineafter(b"> ", b"1")
        r.sendlineafter(b"right > ", f"{right_val:08x}".encode())
        r.sendlineafter(b"subkey > ", b"00000000")
        line = r.recvline().decode().strip()
        core_val = int(line.split("= ")[1], 16)
        sbox_out = rotr32(core_val, 11)
        for i in range(8):
            sboxes[i][v] = (sbox_out >> (4*i)) & 0xF
    return sboxes

def compile_solver(sboxes):
    """Read template, substitute sboxes, compile."""
    with open('./fp_template.c') as f:
        template = f.read()
    
    # Build sbox arrays
    sb = "{" + ",".join(
        "{" + ",".join(str(sboxes[i][j]) for j in range(16)) + "}"
        for i in range(8)
    ) + "}"
    
    inv_sboxes = [[0]*16 for _ in range(8)]
    for i in range(8):
        for j in range(16):
            inv_sboxes[i][sboxes[i][j] & 0xF] = j
    
    isb = "{" + ",".join(
        "{" + ",".join(str(inv_sboxes[i][j]) for j in range(16)) + "}"
        for i in range(8)
    ) + "}"
    
    code = template.replace("__SBOX__", sb).replace("__ISBOX__", isb)
    
    with open('./fp_solver.c', 'w') as f:
        f.write(code)
    
    ret = os.system('gcc -O3 -march=native -fopenmp -o ./fp_solver ./fp_solver.c')
    if ret != 0:
        log.error("Compilation failed!")
        sys.exit(1)
    log.info("C solver compiled")

def find_collision(iv, timeout_sec=120):
    """Run C solver to find 2 fixed-point palindromic keys."""
    L0 = (iv >> 32) & MASK32
    R0 = iv & MASK32
    
    proc = subprocess.Popen(
        ['./fp_solver', f'{L0:08x}', f'{R0:08x}'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    
    try:
        stdout, stderr = proc.communicate(timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
    
    if stderr:
        for line in stderr.strip().split('\n'):
            log.info(f"C: {line}")
    
    keys = []
    for line in stdout.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.strip().split()
        if len(parts) == 4:
            a, b, c, d = [int(x, 16) for x in parts]
            keys.append([a, b, c, d, d, c, b, a])
    
    return keys

def solve():
    HOST = os.environ.get('HOST', 'localhost')
    PORT = int(os.environ.get('PORT', '1337'))
    
    # === Phase 1: Recover S-boxes ===
    log.info("Recovering S-boxes...")
    r = remote(HOST, PORT)

    r.recvuntil(b"run the solver with:\n")
    command = r.recvline()
    res = subprocess.check_output(["bash", "-c", command])
    r.sendline(res)

    r.recvuntil(b"IV = ")
    iv = int(r.recvline().decode().strip(), 16)
    r.recvline()  # Chances line
    
    sboxes = recover_sboxes(r)
    
    for i, sb in enumerate(sboxes):
        log.info(f"S{i}: {sb}")
    
    # Check permutations
    for i in range(8):
        if len(set(sboxes[i])) != 16:
            log.warning(f"S{i} is NOT a permutation!")
    
    # === Phase 2: Compile C solver ===
    compile_solver(sboxes)
    
    # === Phase 3: Find collision, submit ===
    log.info("Getting IV and finding collision...")
    
    t0 = time.time()
    keys = find_collision(iv, timeout_sec=120)
    elapsed = time.time() - t0
    log.info(f"Found {len(keys)} fixed points in {elapsed:.1f}s")
    
    if len(keys) < 2:
        log.error("Need at least 2 fixed points!")
        # Try with more time or different strategy
        r2.close()
        return
    
    m1, m2 = keys[0], keys[1]
    
    # Verify locally
    h1 = dm_compress(iv, m1, sboxes)
    h2 = dm_compress(iv, m2, sboxes)
    log.info(f"m1 = {words_to_hex(m1)}, hash = {h1:016x}")
    log.info(f"m2 = {words_to_hex(m2)}, hash = {h2:016x}")
    assert h1 == h2, f"Hash mismatch: {h1:016x} != {h2:016x}"
    assert m1 != m2, "Messages are identical!"
    log.success(f"Collision verified! Both hash to {h1:016x}")

    r.sendline(b"2")
    r.recvuntil(b"m1 > ")
    r.sendline(words_to_hex(m1))
    r.recvuntil(b"m2 > ")
    r.sendline(words_to_hex(m2))
    r.interactive()
    
    # Submit - need to be within 10s timeout of session 2
    # If we exceeded it, reconnect and quickly resubmit
    total_elapsed = time.time() - t0

solve()
```

C solver `fp_template.c`:

```c
// Optimized fixed-point finder.
// Usage: ./fp L0_hex R0_hex
// Outputs: lines of "a b c d" (hex) for palindromic keys that are fixed
// points.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static const uint8_t SB[8][16] = __SBOX__;
static const uint8_t ISB[8][16] = __ISBOX__;

// 16-bit lookup tables
static uint16_t SLO[65536], SHI[65536];
static uint16_t ISLO[65536], ISHI[65536];

static void init() {
  for (uint32_t v = 0; v < 65536; v++) {
    uint16_t s = 0, is = 0, s2 = 0, is2 = 0;
    for (int i = 0; i < 4; i++) {
      uint8_t n = (v >> (4 * i)) & 0xF;
      s |= (uint16_t)SB[i][n] << (4 * i);
      is |= (uint16_t)ISB[i][n] << (4 * i);
      s2 |= (uint16_t)SB[i + 4][n] << (4 * i);
      is2 |= (uint16_t)ISB[i + 4][n] << (4 * i);
    }
    SLO[v] = s;
    ISLO[v] = is;
    SHI[v] = s2;
    ISHI[v] = is2;
  }
}

#define SL(x) ((uint32_t)SLO[(x) & 0xFFFF] | ((uint32_t)SHI[(x) >> 16] << 16))
#define ISL(x)                                                                 \
  ((uint32_t)ISLO[(x) & 0xFFFF] | ((uint32_t)ISHI[(x) >> 16] << 16))
#define ROTL(x, r) (((x) << (r)) | ((x) >> (32 - (r))))
#define ROTR(x, r) (((x) >> (r)) | ((x) << (32 - (r))))
#define RC(r, k) ROTL(SL((r) + (k)), 11)

static inline void fwd(uint32_t *L, uint32_t *R, uint32_t k) {
  uint32_t t = *R;
  *R = *L ^ RC(*R, k);
  *L = t;
}
static inline void inv(uint32_t *L, uint32_t *R, uint32_t k) {
  uint32_t t = *L;
  *L = *R ^ RC(*L, k);
  *R = t;
}

static volatile int nfound = 0;
typedef struct {
  uint32_t a, b, c, d;
} res_t;
static res_t results[8];

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "Usage: %s L0 R0\n", argv[0]);
    return 1;
  }
  uint32_t L0 = (uint32_t)strtoul(argv[1], NULL, 16);
  uint32_t R0 = (uint32_t)strtoul(argv[2], NULL, 16);
  init();

#pragma omp parallel for schedule(dynamic, 1)
  for (int ab = 0; ab < 65536; ab++) {
    if (nfound >= 2)
      continue;
    uint32_t a = (uint32_t)ab * 0x10007u + 0x13u;
    uint32_t b = (uint32_t)ab * 0x10013u + 0x37u;

    // Fwd: 2 rounds from iv with keys a,b
    uint32_t fL = L0, fR = R0;
    fwd(&fL, &fR, a);
    fwd(&fL, &fR, b);
    // S2 = (fL, fR). For fwd_round(c): T_L=fR (const), T_R=fL^RC(fR,c)
    // So RC_fwd(c) = RC(fR, c) = ROTL(SL(fR+c),11)
    uint32_t fR_const = fR; // = S2_R = T_L (constant)
    uint32_t fL_const = fL; // = S2_L

    // Bwd: inv 2 rounds from iv with keys a,b
    uint32_t bL = L0, bR = R0;
    inv(&bL, &bR, a);
    inv(&bL, &bR, b);
    // S2' = (bL, bR). For inv_round(c): T'_L=bR^RC(bL,c), T'_R=bL(const)
    uint32_t bL_const = bL; // = S2'_L
    uint32_t bR_const = bR; // = S2'_R

    // Constants for equation check
    uint32_t TpR = bL_const; // T'_R is always S2'_L
    uint32_t TL = fR_const;  // T_L is always S2_R

    for (uint64_t c64 = 0; c64 <= 0xFFFFFFFFULL; c64++) {
      if (__builtin_expect(nfound >= 2, 0))
        break;
      uint32_t c = (uint32_t)c64;

      // Compute fwd round output
      uint32_t rc_fwd = ROTL(SL(fR_const + c), 11);
      uint32_t TR = fL_const ^ rc_fwd;

      // Compute bwd round output
      uint32_t rc_bwd = ROTL(SL(bL_const + c), 11);
      uint32_t TpL = bR_const ^ rc_bwd;

      // Eq1: d = ISL(ROTR(TR ^ TpR, 11)) - TpL
      uint32_t d = ISL(ROTR(TR ^ TpR, 11)) - TpL;

      // Eq2: SL(TR + d) == ROTR(TL ^ TpL, 11)
      if (__builtin_expect(SL(TR + d) != ROTR(TL ^ TpL, 11), 1))
        continue;

      // Full 8-round verify
      uint32_t vL = L0, vR = R0;
      uint32_t ks[8] = {a, b, c, d, d, c, b, a};
      for (int r = 0; r < 8; r++)
        fwd(&vL, &vR, ks[r]);
      if (vL == L0 && vR == R0) {
#pragma omp critical
        {
          if (nfound < 8) {
            results[nfound] = (res_t){a, b, c, d};
            nfound++;
            fprintf(stderr, "Found #%d: %08x %08x %08x %08x\n", nfound, a, b, c,
                    d);
          }
        }
        break;
      }
    }
  }

  for (int i = 0; i < nfound && i < 2; i++)
    printf("%08x %08x %08x %08x\n", results[i].a, results[i].b, results[i].c,
           results[i].d);
  return 0;
}
```
