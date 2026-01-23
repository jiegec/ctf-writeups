# Day 10 Jingle's Validator

Decompile the attachment:

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  _BOOL4 v3; // ebx
  size_t v4; // rax
  char *v6; // rsi
  _DWORD *v7; // rdi
  __int64 i; // rcx
  _DWORD *v9; // rdi
  __int64 j; // rcx
  char v11; // r11
  _BOOL8 flags; // r10
  unsigned __int64 pc; // rdx
  char *v14; // rax
  unsigned __int8 rd; // si
  unsigned __int8 rs1; // di
  unsigned __int16 imm; // cx
  unsigned __int64 v18; // rax
  int v19; // ecx
  unsigned __int64 v20; // rax
  unsigned __int64 v21; // rax
  int v22; // ecx
  unsigned __int64 v23; // rax
  int v24; // ecx
  int valid; // eax
  _DWORD regs[92]; // [rsp+0h] [rbp-3A8h] BYREF
  char s[256]; // [rsp+170h] [rbp-238h] BYREF
  _BYTE v28[264]; // [rsp+270h] [rbp-138h] BYREF
  unsigned __int64 v29; // [rsp+378h] [rbp-30h]

  v29 = __readfsqword(0x28u);
  puts("[*] NPLD Tool Suite v2.4.1");
  __printf_chk(1, "Enter license key: ");
  if ( !fgets(s, 256, stdin) )
    return 1;
  v4 = strcspn(s, "\n");
  s[v4] = 0;
  if ( v4 == 52 )
  {
    v6 = s;
    v7 = v28;
    for ( i = 13; i; --i )
    {
      *v7 = *(_DWORD *)v6;
      v6 += 4;
      ++v7;
    }
    memset(&regs[16], 0, 0x128u);
    *(_QWORD *)&regs[16] = v28;
    *(_QWORD *)&regs[18] = byte_20E0;
    *(_QWORD *)&regs[20] = 52;
    *(_QWORD *)&regs[22] = 52;
    regs[88] = 62263;
    v9 = regs;
    for ( j = 13; j; --j )
      *v9++ = 0;
    regs[0] = 52;
    regs[9] = 62263;
    v11 = 0;
    flags = 0;
    pc = 0;
    do
    {
      v14 = (char *)&unk_2120 + 6 * pc;
      rd = v14[1];
      rs1 = v14[2];
      imm = *((_WORD *)v14 + 2);
      switch ( *v14 )
      {
        case 0:
          regs[rd] = (__int16)imm;
          goto LABEL_12;
        case 1:
          regs[rd] = regs[rs1];
          goto LABEL_12;
        case 2:
          regs[rd] += (__int16)imm;
          goto LABEL_12;
        case 3:
          regs[rd] += regs[rs1];
          goto LABEL_12;
        case 4:
          regs[rd] -= (__int16)imm;
          goto LABEL_12;
        case 5:
          regs[rd] -= regs[rs1];
          goto LABEL_12;
        case 6:
          regs[rd] ^= regs[rs1];
          goto LABEL_12;
        case 7:
          regs[rd] |= regs[rs1];
          goto LABEL_12;
        case 8:
          regs[rd] = regs[rs1] << imm;
          goto LABEL_12;
        case 9:
          regs[rd] = regs[rs1] >> imm;
          goto LABEL_12;
        case 10:
          regs[rd] &= imm;
          goto LABEL_12;
        case 11:
          v18 = (__int16)imm + (unsigned __int64)(unsigned int)regs[rs1];
          v19 = 0;
          if ( v18 <= 0x33 )
            v19 = (unsigned __int8)v28[v18];
          regs[rd] = v19;
          goto LABEL_12;
        case 12:
          v20 = (__int16)imm + (unsigned __int64)(unsigned int)regs[rs1];
          if ( v20 <= 0xFF )
            *((_BYTE *)&regs[24] + v20) = regs[rd];
          goto LABEL_12;
        case 13:
          v21 = (__int16)imm + (unsigned __int64)(unsigned int)regs[rs1];
          v22 = 0;
          if ( v21 <= 0x33 )
            v22 = *((unsigned __int8 *)&regs[24] + v21);
          regs[rd] = v22;
          goto LABEL_12;
        case 14:
          v23 = (__int16)imm + (unsigned __int64)(unsigned int)regs[rs1];
          v24 = 0;
          if ( v23 <= 0x33 )
            v24 = byte_20E0[v23];
          regs[rd] = v24;
          goto LABEL_12;
        case 15:
          flags = regs[rd] < (unsigned int)(__int16)imm;
          goto LABEL_12;
        case 16:
          flags = regs[rd] == (__int16)imm;
          goto LABEL_12;
        case 17:
          flags = regs[rd] == regs[rs1];
          goto LABEL_12;
        case 18:
          pc = (__int16)imm;
          break;
        case 19:
          if ( !flags )
            goto LABEL_12;
          pc = (__int16)imm;
          break;
        case 20:
          if ( flags )
            goto LABEL_12;
          pc = (__int16)imm;
          break;
        case 21:
          v3 = imm != 0;
          v11 = 1;
          goto LABEL_12;
        case 22:
          if ( v11 )
            regs[89] = v3;
          valid = regs[89];
          goto LABEL_51;
        default:
LABEL_12:
          ++pc;
          break;
      }
    }
    while ( pc <= 0x9B );
    if ( v11 )
      regs[89] = v3;
    valid = regs[89];
LABEL_51:
    if ( valid )
    {
      puts("[+] License valid.");
      return 0;
    }
    else
    {
      puts("[-] Invalid license key.");
      return 1;
    }
  }
  else
  {
    puts("[-] Invalid license key.");
    return 1;
  }
}
```

It is a VM, containing the following ops:

- 0: "mov_imm",
- 1: "mov_reg",
- 2: "add_imm",
- 3: "add_reg",
- 4: "sub_imm",
- 5: "sub_reg",
- 6: "xor_reg",
- 7: "or_reg",
- 8: "shl_imm",
- 9: "shr_imm",
- 10: "and_imm",
- 11: "ld_input",
- 12: "st_mem",
- 13: "ld_mem",
- 14: "ld_const",
- 15: "cmp_lt_imm",
- 16: "cmp_eq_imm",
- 17: "cmp_eq_reg",
- 18: "jmp",
- 19: "jmp_true",
- 20: "jmp_false",
- 21: "set_flag",
- 22: "return",

The bytecodes are stored in an array starting from 0x2120. Disassemble the bytecode and convert them to RISCV-32 assembly so that we can use existing decompiler:

```python
#!/usr/bin/env python3
import struct

with open("jollyvm", "rb") as f:
    data = f.read()

bytecode = data[0x2120 : 0x2120 + 156 * 6]
const_data = data[0x20E0 : 0x20E0 + 52]

open("const.bin", "wb").write(const_data)

# Parse instructions
instructions = []
for i in range(0, len(bytecode), 6):
    instr = bytecode[i : i + 6]
    if len(instr) < 6:
        break
    opcode = instr[0]
    reg1 = instr[1]
    reg2 = instr[2]
    # Immediate is at bytes 4-5 (little-endian 16-bit)
    imm = struct.unpack("<H", instr[4:6])[0]
    instructions.append((i // 6, opcode, reg1, reg2, imm))

opcode_names = {
    0: "mov_imm",
    1: "mov_reg",
    2: "add_imm",
    3: "add_reg",
    4: "sub_imm",
    5: "sub_reg",
    6: "xor_reg",
    7: "or_reg",
    8: "shl_imm",
    9: "shr_imm",
    10: "and_imm",
    11: "ld_input",
    12: "st_mem",
    13: "ld_mem",
    14: "ld_const",
    15: "cmp_lt_imm",
    16: "cmp_eq_imm",
    17: "cmp_eq_reg",
    18: "jmp",
    19: "jmp_true",
    20: "jmp_false",
    21: "set_flag",
    22: "return",
}

print("Full bytecode analysis:")
print("=" * 80)

# Print all instructions
for idx, (addr, op, r1, r2, imm) in enumerate(instructions):
    opname = opcode_names.get(op, f"unk_{op}")
    print(f"{idx:3d}: {opname:12} r{r1}, r{r2}, imm={imm}")

# convert to assembly
# input: saved in x10
# const: saved in x11
# memory buffer: saved in x12
# map r0-r12: x18-x30
# tmp: x9
offset = 18
# flag: x31
flag = "x31"

file = open("test.asm", "w")
print(".text", file=file)
print(".global work", file=file)
print("work:", file=file)
# zero initialize
for i in range(0, 13):
    print(f"\tli x{i+offset}, 0", file=file)
# r0 = 52
print(f"\tli x{0+offset}, 52", file=file)
# r9 = 62263
print(f"\tli x{9+offset}, 62263", file=file)

for idx, (addr, op, r1, r2, imm) in enumerate(instructions):
    print(f"_L{idx}:", file=file)
    if op == 0:
        # mov_imm
        print(f"\tli x{r1+offset}, {imm}", file=file)
    elif op == 1:
        # mov_reg
        print(f"\tmv x{r1+offset}, x{r2+offset}", file=file)
    elif op == 2:
        # add_imm
        print(f"\taddi x{r1+offset}, x{r1+offset}, {imm}", file=file)
    elif op == 4:
        # sub_imm
        print(f"\taddi x{r1+offset}, x{r1+offset}, {-imm}", file=file)
    elif op == 5:
        # sub_reg
        print(f"\tsub x{r1+offset}, x{r1+offset}, x{r2+offset}", file=file)
    elif op == 6:
        # xor_reg
        print(f"\txor x{r1+offset}, x{r1+offset}, x{r2+offset}", file=file)
    elif op == 7:
        # or_reg
        print(f"\tor x{r1+offset}, x{r1+offset}, x{r2+offset}", file=file)
    elif op == 8:
        # shl_imm
        print(f"\tslli x{r1+offset}, x{r2+offset}, {imm}", file=file)
    elif op == 9:
        # shr_imm
        print(f"\tsrli x{r1+offset}, x{r2+offset}, {imm}", file=file)
    elif op == 10:
        # and_imm
        print(f"\tandi x{r1+offset}, x{r1+offset}, {imm}", file=file)
    elif op == 11:
        # ld_input
        print(f"\tadd x9, x10, x{r2+offset}", file=file)
        print(f"\tlbu x{r1+offset}, {imm}(x9)", file=file)
    elif op == 12:
        # st_mem
        print(f"\tadd x9, x12, x{r2+offset}", file=file)
        print(f"\tsb x{r1+offset}, {imm}(x9)", file=file)
    elif op == 13:
        # ld_mem
        print(f"\tadd x9, x12, x{r2+offset}", file=file)
        print(f"\tlbu x{r1+offset}, {imm}(x9)", file=file)
    elif op == 14:
        # ld_const
        print(f"\tadd x9, x11, x{r2+offset}", file=file)
        print(f"\tlbu x{r1+offset}, {imm}(x9)", file=file)
    elif op == 15:
        # cmp_lt_imm
        print(f"\tsltiu {flag}, x{r1+offset}, {imm}", file=file)
    elif op == 16:
        # cmp_eq_imm
        print(f"\taddi x9, x{r1+offset}, {-imm}", file=file)
        print(f"\tseqz {flag}, x9", file=file)
    elif op == 17:
        # cmp_eq_reg
        print(f"\tsub x9, x{r1+offset}, x{r2+offset}", file=file)
        print(f"\tseqz {flag}, x9", file=file)
    elif op == 18:
        # jmp
        print(f"\tj _L{imm}", file=file)
    elif op == 19:
        # jmp_true
        print(f"\tbnez {flag}, _L{imm}", file=file)
    elif op == 20:
        # jmp_false
        print(f"\tbeqz {flag}, _L{imm}", file=file)
    elif op == 21:
        # set_flag
        print(f"\tli x10, {imm}", file=file)
    elif op == 22:
        # get_flag
        print(f"\tret", file=file)
    else:
        print("TODO", op, opcode_names[op])
```

Output disassembly:

```asm
Full bytecode analysis:
================================================================================
  0: cmp_lt_imm   r0, r0, imm=4
  1: jmp_true     r0, r0, imm=5
  2: mov_reg      r2, r0, imm=0
  3: sub_imm      r2, r0, imm=4
  4: jmp          r0, r0, imm=6
  5: mov_imm      r2, r0, imm=0
  6: mov_imm      r3, r0, imm=0
  7: mov_reg      r4, r2, imm=0
  8: add_imm      r4, r0, imm=0
  9: ld_input     r5, r4, imm=0
 10: shl_imm      r5, r5, imm=0
 11: or_reg       r3, r5, imm=0
 12: mov_reg      r4, r2, imm=0
 13: add_imm      r4, r0, imm=1
 14: ld_input     r5, r4, imm=0
 15: shl_imm      r5, r5, imm=8
 16: or_reg       r3, r5, imm=0
 17: mov_reg      r4, r2, imm=0
 18: add_imm      r4, r0, imm=2
 19: ld_input     r5, r4, imm=0
 20: shl_imm      r5, r5, imm=16
 21: or_reg       r3, r5, imm=0
 22: mov_reg      r4, r2, imm=0
 23: add_imm      r4, r0, imm=3
 24: ld_input     r5, r4, imm=0
 25: shl_imm      r5, r5, imm=24
 26: or_reg       r3, r5, imm=0
 27: mov_reg      r4, r3, imm=0
 28: shr_imm      r4, r4, imm=3
 29: mov_reg      r5, r3, imm=0
 30: shr_imm      r5, r5, imm=5
 31: xor_reg      r4, r5, imm=0
 32: mov_reg      r5, r3, imm=0
 33: shr_imm      r5, r5, imm=8
 34: xor_reg      r4, r5, imm=0
 35: mov_reg      r5, r3, imm=0
 36: shr_imm      r5, r5, imm=12
 37: xor_reg      r4, r5, imm=0
 38: and_imm      r4, r0, imm=255
 39: mov_reg      r5, r9, imm=0
 40: shl_imm      r5, r5, imm=8
 41: mov_reg      r9, r5, imm=0
 42: or_reg       r9, r4, imm=0
 43: mov_reg      r10, r9, imm=0
 44: mov_reg      r5, r0, imm=0
 45: sub_reg      r5, r1, imm=0
 46: cmp_eq_imm   r5, r0, imm=0
 47: jmp_true     r0, r0, imm=141
 48: cmp_lt_imm   r5, r0, imm=4
 49: jmp_true     r0, r0, imm=52
 50: mov_imm      r8, r0, imm=4
 51: jmp          r0, r0, imm=53
 52: mov_reg      r8, r5, imm=0
 53: mov_reg      r4, r9, imm=0
 54: shr_imm      r4, r4, imm=3
 55: mov_reg      r5, r9, imm=0
 56: shr_imm      r5, r5, imm=5
 57: xor_reg      r4, r5, imm=0
 58: mov_reg      r5, r9, imm=0
 59: shr_imm      r5, r5, imm=8
 60: xor_reg      r4, r5, imm=0
 61: mov_reg      r5, r9, imm=0
 62: shr_imm      r5, r5, imm=12
 63: xor_reg      r4, r5, imm=0
 64: and_imm      r4, r0, imm=255
 65: mov_reg      r5, r9, imm=0
 66: shl_imm      r5, r5, imm=8
 67: mov_reg      r9, r5, imm=0
 68: or_reg       r9, r4, imm=0
 69: mov_reg      r10, r9, imm=0
 70: mov_imm      r11, r0, imm=0
 71: cmp_lt_imm   r8, r0, imm=1
 72: jmp_true     r0, r0, imm=84
 73: mov_reg      r4, r1, imm=0
 74: ld_input     r5, r4, imm=0
 75: mov_reg      r6, r10, imm=0
 76: shr_imm      r6, r6, imm=0
 77: and_imm      r6, r0, imm=255
 78: mov_reg      r7, r5, imm=0
 79: xor_reg      r7, r6, imm=0
 80: st_mem       r7, r1, imm=0
 81: mov_reg      r6, r5, imm=0
 82: shl_imm      r6, r6, imm=0
 83: or_reg       r11, r6, imm=0
 84: cmp_lt_imm   r8, r0, imm=2
 85: jmp_true     r0, r0, imm=97
 86: mov_reg      r4, r1, imm=0
 87: ld_input     r5, r4, imm=1
 88: mov_reg      r6, r10, imm=0
 89: shr_imm      r6, r6, imm=8
 90: and_imm      r6, r0, imm=255
 91: mov_reg      r7, r5, imm=0
 92: xor_reg      r7, r6, imm=0
 93: st_mem       r7, r1, imm=1
 94: mov_reg      r6, r5, imm=0
 95: shl_imm      r6, r6, imm=8
 96: or_reg       r11, r6, imm=0
 97: cmp_lt_imm   r8, r0, imm=3
 98: jmp_true     r0, r0, imm=110
 99: mov_reg      r4, r1, imm=0
100: ld_input     r5, r4, imm=2
101: mov_reg      r6, r10, imm=0
102: shr_imm      r6, r6, imm=16
103: and_imm      r6, r0, imm=255
104: mov_reg      r7, r5, imm=0
105: xor_reg      r7, r6, imm=0
106: st_mem       r7, r1, imm=2
107: mov_reg      r6, r5, imm=0
108: shl_imm      r6, r6, imm=16
109: or_reg       r11, r6, imm=0
110: cmp_lt_imm   r8, r0, imm=4
111: jmp_true     r0, r0, imm=123
112: mov_reg      r4, r1, imm=0
113: ld_input     r5, r4, imm=3
114: mov_reg      r6, r10, imm=0
115: shr_imm      r6, r6, imm=24
116: and_imm      r6, r0, imm=255
117: mov_reg      r7, r5, imm=0
118: xor_reg      r7, r6, imm=0
119: st_mem       r7, r1, imm=3
120: mov_reg      r6, r5, imm=0
121: shl_imm      r6, r6, imm=24
122: or_reg       r11, r6, imm=0
123: mov_reg      r4, r11, imm=0
124: shr_imm      r4, r4, imm=3
125: mov_reg      r5, r11, imm=0
126: shr_imm      r5, r5, imm=5
127: xor_reg      r4, r5, imm=0
128: mov_reg      r5, r11, imm=0
129: shr_imm      r5, r5, imm=8
130: xor_reg      r4, r5, imm=0
131: mov_reg      r5, r11, imm=0
132: shr_imm      r5, r5, imm=12
133: xor_reg      r4, r5, imm=0
134: and_imm      r4, r0, imm=255
135: mov_reg      r5, r9, imm=0
136: shl_imm      r5, r5, imm=8
137: mov_reg      r9, r5, imm=0
138: or_reg       r9, r4, imm=0
139: add_imm      r1, r0, imm=4
140: jmp          r0, r0, imm=44
141: mov_imm      r12, r0, imm=0
142: mov_reg      r4, r0, imm=0
143: sub_reg      r4, r12, imm=0
144: cmp_eq_imm   r4, r0, imm=0
145: jmp_true     r0, r0, imm=154
146: ld_mem       r5, r12, imm=0
147: ld_const     r6, r12, imm=0
148: cmp_eq_reg   r5, r6, imm=0
149: jmp_false    r0, r0, imm=152
150: add_imm      r12, r0, imm=1
151: jmp          r0, r0, imm=142
152: set_flag     r0, r0, imm=0
153: return       r0, r0, imm=0
154: set_flag     r0, r0, imm=1
155: return       r0, r0, imm=0
```

Decompile the RISC-V 32 binary gets:

```c
// Alternative name is '$xrv32i2p0_m2p0_a2p0_f2p0_d2p0_c2p0_zmmul1p0_zaamo1p0_zalrsc1p0'
int __fastcall work(unsigned __int8 *a1, unsigned __int8 *a2, unsigned __int8 *a3)
{
  int v3; // s3
  unsigned __int8 *v4; // s1
  unsigned int v5; // s11
  unsigned int v6; // s10
  int v7; // s11
  unsigned int v8; // t4
  unsigned int v9; // s7
  int v10; // s7
  int v11; // s7
  int v12; // s7
  int i; // t5

  v3 = 0;
  v4 = a1 + 51;
  v5 = (unsigned __int8)(((unsigned int)(a1[48] | (a1[49] << 8) | (a1[50] << 16) | (*v4 << 24)) >> 3)
                       ^ ((unsigned int)(a1[48] | (a1[49] << 8) | (a1[50] << 16) | (*v4 << 24)) >> 5)
                       ^ a1[49]
                       ^ ((unsigned int)(a1[48] | (a1[49] << 8) | (a1[50] << 16) | (*v4 << 24)) >> 12))
     | 0xF33700;
  while ( v3 != 52 )
  {
    if ( (unsigned int)(52 - v3) < 4 )
      v6 = 52 - v3;
    else
      v6 = 4;
    v7 = (v5 << 8) | (unsigned __int8)((v5 >> 3) ^ (v5 >> 5) ^ BYTE1(v5) ^ (v5 >> 12));
    v8 = 0;
    if ( v6 )
    {
      v9 = a1[v3];
      a3[v3] = a1[v3] ^ v7;
      v8 = v9;
    }
    if ( v6 >= 2 )
    {
      v10 = a1[v3 + 1];
      a3[v3 + 1] = a1[v3 + 1] ^ BYTE1(v7);
      v8 |= v10 << 8;
    }
    if ( v6 >= 3 )
    {
      v11 = a1[v3 + 2];
      a3[v3 + 2] = a1[v3 + 2] ^ BYTE2(v7);
      v8 |= v11 << 16;
    }
    if ( v6 >= 4 )
    {
      v12 = a1[v3 + 3];
      a3[v3 + 3] = a1[v3 + 3] ^ HIBYTE(v7);
      v8 |= v12 << 24;
    }
    v5 = (v7 << 8) | (unsigned __int8)((v8 >> 3) ^ (v8 >> 5) ^ BYTE1(v8) ^ (v8 >> 12));
    v3 += 4;
  }
  for ( i = 0; i != 52; ++i )
  {
    if ( a3[i] != a2[i] )
      return 0;
  }
  return 1;
}
```

Our input is `a1`, `a2` is a constant array saved at 0x20E0 of the attachment, `a3` is a temporary buffer. We need to find the valid input to let the function return 1. Let DeepSeek write the solve script:

```python
#!/usr/bin/env python3

def read_const_bin():
    with open('const.bin', 'rb') as f:
        return f.read()

def f_transform(x):
    """Implements: (x >> 3) ^ (x >> 5) ^ BYTE1(x) ^ (x >> 12)"""
    byte1 = (x >> 8) & 0xFF
    return ((x >> 3) ^ (x >> 5) ^ byte1 ^ (x >> 12)) & 0xFF

def verify_solution(input_bytes, target_bytes):
    """Verify that input produces target"""
    # Reimplement forward algorithm
    a1 = bytearray(input_bytes)
    a3 = bytearray(52)
    
    last_word = (a1[48] | (a1[49] << 8) | (a1[50] << 16) | (a1[51] << 24))
    v5 = (f_transform(last_word) | 0xF33700) & 0xFFFFFFFF
    
    v3 = 0
    while v3 != 52:
        if (52 - v3) < 4:
            v6 = 52 - v3
        else:
            v6 = 4
        
        v7 = ((v5 << 8) | f_transform(v5)) & 0xFFFFFFFF
        
        v8 = 0
        if v6 >= 1:
            a3[v3] = a1[v3] ^ (v7 & 0xFF)
            v8 = a1[v3]
        
        if v6 >= 2:
            a3[v3 + 1] = a1[v3 + 1] ^ ((v7 >> 8) & 0xFF)
            v8 |= a1[v3 + 1] << 8
        
        if v6 >= 3:
            a3[v3 + 2] = a1[v3 + 2] ^ ((v7 >> 16) & 0xFF)
            v8 |= a1[v3 + 2] << 16
        
        if v6 >= 4:
            a3[v3 + 3] = a1[v3 + 3] ^ ((v7 >> 24) & 0xFF)
            v8 |= a1[v3 + 3] << 24
        
        v5 = ((v7 << 8) | f_transform(v8)) & 0xFFFFFFFF
        v3 += 4
    
    return bytes(a3) == target_bytes

def main():
    target = read_const_bin()
    print(f"Target: {target.hex()}")
    
    # The algorithm seems reversible if we know last word
    # But last word affects initial v5, which affects everything
    
    # Actually, we can brute force last word (32 bits = 4.3 billion)
    # Too many... but maybe we can reduce search space
    
    # Notice: v5 = (f_transform(last_word) | 0xF33700)
    # So v5 is 0xF337?? where ?? is f_transform(last_word)
    # f_transform produces a byte, so only 256 possibilities for initial v5!
    
    print("Brute forcing initial v5 possibilities...")
    
    solutions = []
    
    for ft in range(256):
        # ft is f_transform(last_word)
        v5_initial = ft | 0xF33700
        
        # Now we need to find last_word that produces this ft
        # But we don't actually need last_word if we have v5_initial
        # We can work forward with v5_initial
        
        # Try to reconstruct input using v5_initial
        input_bytes = bytearray(52)
        target_arr = bytearray(target)
        
        v5 = v5_initial
        v3 = 0
        success = True
        
        while v3 < 52:
            if (52 - v3) < 4:
                v6 = 52 - v3
            else:
                v6 = 4
            
            v7 = ((v5 << 8) | f_transform(v5)) & 0xFFFFFFFF
            
            # Recover input
            if v6 >= 1:
                input_bytes[v3] = target_arr[v3] ^ (v7 & 0xFF)
            if v6 >= 2:
                input_bytes[v3 + 1] = target_arr[v3 + 1] ^ ((v7 >> 8) & 0xFF)
            if v6 >= 3:
                input_bytes[v3 + 2] = target_arr[v3 + 2] ^ ((v7 >> 16) & 0xFF)
            if v6 >= 4:
                input_bytes[v3 + 3] = target_arr[v3 + 3] ^ ((v7 >> 24) & 0xFF)
            
            # Compute v8
            v8 = 0
            if v6 >= 1:
                v8 |= input_bytes[v3]
            if v6 >= 2:
                v8 |= input_bytes[v3 + 1] << 8
            if v6 >= 3:
                v8 |= input_bytes[v3 + 2] << 16
            if v6 >= 4:
                v8 |= input_bytes[v3 + 3] << 24
            
            # Update v5 for next iteration
            v5 = ((v7 << 8) | f_transform(v8)) & 0xFFFFFFFF
            v3 += 4
        
        # Now we have candidate input
        # Check if it's consistent: last word should produce correct f_transform
        last_word = (input_bytes[48] | (input_bytes[49] << 8) | 
                    (input_bytes[50] << 16) | (input_bytes[51] << 24))
        
        if f_transform(last_word) == ft:
            # Verify full solution
            if verify_solution(bytes(input_bytes), target):
                solutions.append(bytes(input_bytes))
                print(f"Found solution with ft={ft:02x}")
                print(f"Input: {bytes(input_bytes).hex()}")
                print(f"Last word: {last_word:08x}")
    
    if solutions:
        print(f"\nFound {len(solutions)} solution(s)")
        for i, sol in enumerate(solutions):
            print(f"\nSolution {i+1}:")
            print(f"Hex: {sol.hex()}")
            print(f"ASCII: {sol}")
            
            # Check if it looks like flag
            if b'CTF{' in sol or b'flag{' in sol:
                print("Contains flag pattern!")
    else:
        print("No solutions found")

if __name__ == "__main__":
    main()
```

Output:

```
Target: 3c6f5388d5f60028b5bcab8b4da6e29a5b5710a459d95636010451b0e1e2040ce235f8886a2ccf29ea2e737e2acce95f543567d2
Brute forcing initial v5 possibilities...
Found solution with ft=1c
Input: 6373647b49355f346e793748694e395f5233344c6c595f52344e64306d5f31465f6974355f627275373346307263344231653f7d
Last word: 7d3f6531

Found 1 solution(s)

Solution 1:
Hex: 6373647b49355f346e793748694e395f5233344c6c595f52344e64306d5f31465f6974355f627275373346307263344231653f7d
ASCII: b'csd{I5_4ny7HiN9_R34LlY_R4Nd0m_1F_it5_bru73F0rc4B1e?}'
```
