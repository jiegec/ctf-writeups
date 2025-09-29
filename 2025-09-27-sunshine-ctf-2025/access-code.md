# Access Code

```
Here's the program cartridge for the satellite terminal's login system. We need the access code to start exploring the system.

    AccessCode.peg
```

Disassemble the code using the debugger:

```
@puts:
        0300.0000: MOV     A3, 0x7F
        0304.0000: LDB     A1, [A0]
        0306.0000: INC     A0, 1
        0308.0000: AND     A2, A1, A3
        030B.0000: WRB     (0), A2
        030D.0000: CMP     A1, A2
        030F.0000: BRR.NE  @puts+0x4 //0304.0000
        0312.0000: RET
@print_hex_byte:
        0314.0000: ADD     A5, PC, 0x3A
        0319.0000: SRU     A3, A0, 0x4
        031D.0000: LDB     A4, [A5 + A3]
        0320.0000: WRB     (0), A4
        0322.0000: AND     A0, 0xF
        0326.0000: LDB     A4, [A5 + A0]
        0329.0000: WRB     (0), A4
        032B.0000: RET
@print_hex:
        032D.0000: MOV     A1, A1
        032F.0000: RET.EQ
        0331.0000: ADD     A5, PC, 0x1D
        0336.0000: LDB     A2, [A0]
        0338.0000: SRU     A3, A2, 0x4
        033C.0000: LDB     A4, [A5 + A3]
        033F.0000: WRB     (0), A4
        0341.0000: AND     A2, 0xF
        0345.0000: LDB     A4, [A5 + A2]
        0348.0000: WRB     (0), A4
        034A.0000: INC     A0, 1
        034C.0000: INC     A1, -1
        034E.0000: BRR.NE  @print_hex+0x9 //0336.0000
        0351.0000: RET
        0353.0000: LDW.NE  A2, [A0]
        0355.0000: LDB.NE  A2, [A2]
        0357.0000: BRA.NE  A2, A4
        0359.0000: FCA.NE  A2, S0
        035B.0000: RDB.NE  A2, (9)
        035D.0000: SUB.LE  A5, A1
        035F.0000: MLS.LE  A5, A3
        0361.0000: DVS.LE  A5, A5
@gimli_dump_state:
        0363.0000: PSH     {S0-S1, FP, RA-RD}
        0366.0000: INC     FP, SP, 4
        0369.0000: MOV     S0, A0
        036B.0000: WRB     (0), 0x20
        036E.0000: WRB     (0), 0x20
        0371.0000: MOV     S1, ZERO
        0373.0000: MOV     S1, S1
        0375.0000: BRR.EQ  @gimli_dump_state+0x31 //0394.0000
        0378.0000: AND     ZERO, S1, 0xF
        037D.0000: BRR.NE  @gimli_dump_state+0x29 //038C.0000
        0380.0000: WRB     (0), 0xA
        0383.0000: WRB     (0), 0x20
        0386.0000: WRB     (0), 0x20
        0389.0000: BRR     @gimli_dump_state+0x31 //0394.0000
        038C.0000: AND     ZERO, S1, 0x3
        0391.0000: WRB.EQ  (0), 0x20
        0394.0000: LDB     A0, [S0 + S1]
        0397.0000: FCR     @print_hex_byte
        039A.0000: INC     S1, 1
        039C.0000: CMP     S1, 0x30
        03A0.0000: BRR.LT  @gimli_dump_state+0x10 //0373.0000
        03A3.0000: WRB     (0), 0xA
        03A6.0000: INC     SP, FP, -4
        03A9.0000: POP     {S0-S1, FP, PC-DPC}
        03AC.0000: SUB.GE  FP, A0
        03AE.0000: SUB.GE  FP, A0
        03B0.0000: SUB.GE  RA, S0
        03B2.0000: SHL     PC, RD
        03B4.0000: MOV     PC, S2
        03B6.0000: SUB.GE  FP, A0
        03B8.0000: SUB.GE  FP, A0
        03BA.0000: SUB.GE  ZERO, FP
@gimli:
        03BC.0000: PSH     {S0-FP, RA-RD}
        03BF.0000: MOV     A1, 0x18
        03C3.0000: PSH     {A1}
        03C6.0000: MOV     A2, ZERO
        03C8.0000: POP     A0, {A3-A4}
        03CC.0000: SHL     RA, A3, 0x8
        03D0.0000: SHL     RD, A4, 0x8
        03D4.0000: SRU     A3, 0x8
        03D7.0000: ORR     A3, RD
        03D9.0000: SRU     A4, 0x8
        03DC.0000: ORR     A4, RA
        03DE.0000: ADD     A0, 0xC
        03E2.0000: POP     A0, {A5-S0}
        03E6.0000: SRU     RA, A5, 0x7
        03EA.0000: SRU     RD, S0, 0x7
        03EE.0000: SHL     A5, 0x9
        03F1.0000: ORR     A5, RD
        03F3.0000: SHL     S0, 0x9
        03F6.0000: ORR     S0, RA
        03F8.0000: ADD     A0, 0xC
        03FC.0000: POP     A0, {S1-S2}
        0400.0000: AND     RA, A5, S1
        0403.0000: AND     RD, S0, S2
        0406.0000: SRU     A1, RA, 0xE
        040A.0000: SHL     RA, 0x2
        040D.0000: SHL     RD, 0x2
        0410.0000: ORR     RD, A1
        0412.0000: SHL     FP, S2, 0x1
        0416.0000: SHL     A1, S1, 0x1
        041A.0000: ORR.GE  FP, 0x1
        041E.0000: XOR     RA, A1
        0420.0000: XOR     RD, FP
        0422.0000: XOR     RA, A3
        0424.0000: XOR     RD, A4
        0426.0000: PSH     A0, {RA-RD}
        042A.0000: ORR     RA, A3, S1
        042D.0000: ORR     RD, A4, S2
        0430.0000: SHL     RD, 0x1
        0433.0000: SHL     RA, 0x1
        0436.0000: ORR.GE  RD, 0x1
        043A.0000: XOR     RA, A3
        043C.0000: XOR     RD, A4
        043E.0000: XOR     RA, A5
        0440.0000: XOR     RD, S0
        0442.0000: SUB     A0, 0xC
        0446.0000: PSH     A0, {RA-RD}
        044A.0000: AND     RA, A3, A5
        044D.0000: AND     RD, A4, S0
        0450.0000: SRU     A1, RA, 0xD
        0454.0000: SHL     RA, 0x3
        0457.0000: SHL     RD, 0x3
        045A.0000: ORR     RD, A1
        045C.0000: XOR     RA, A5
        045E.0000: XOR     RD, S0
        0460.0000: XOR     RA, S1
        0462.0000: XOR     RD, S2
        0464.0000: SUB     A0, 0xC
        0468.0000: PSH     A0, {RA-RD}
        046C.0000: INC     A0, 4
        046E.0000: INC     A2, 1
        0470.0000: CMP     A2, 0x4
        0474.0000: BRR.LT  @gimli+0xc //03C8.0000
        0477.0000: SUB     A0, 0x10
        047B.0000: POP     {A1}
        047E.0000: SRU     A2, A1, 0x1
        0482.0000: BRR.GE  @gimli+0x125 //04E1.0000
        0485.0000: SRU     A2, 0x1
        0488.0000: BRR.GE  @gimli+0xf9 //04B5.0000
        048B.0000: POP     A0, {A3-S0}
        048F.0000: PSH     A0, {A3-A4}
        0493.0000: XOR     S0, 0x9E37
        0497.0000: ORR     A3, A1, 0x7900
        049C.0000: XOR     A5, A3
        049E.0000: PSH     A0, {A5-S0}
        04A2.0000: INC     A0, 8
        04A4.0000: POP     A0, {A3-S0}
        04A8.0000: PSH     A0, {A3-A4}
        04AC.0000: PSH     A0, {A5-S0}
        04B0.0000: INC     A0, -8
        04B2.0000: BRR     @gimli+0x125 //04E1.0000
        04B5.0000: POP     A0, {A3-A4}
        04B9.0000: INC     A0, 4
        04BB.0000: POP     A0, {A5-S0}
        04BF.0000: PSH     A0, {A3-A4}
        04C3.0000: INC     A0, -4
        04C5.0000: PSH     A0, {A5-S0}
        04C9.0000: INC     A0, 4
        04CB.0000: POP     A0, {A3-A4}
        04CF.0000: INC     A0, 4
        04D1.0000: POP     A0, {A5-S0}
        04D5.0000: PSH     A0, {A3-A4}
        04D9.0000: INC     A0, -4
        04DB.0000: PSH     A0, {A5-S0}
        04DF.0000: INC     A0, -4
        04E1.0000: INC     A1, -1
        04E3.0000: BRR.NE  @gimli+0x7 //03C3.0000
        04E6.0000: POP     {S0-FP, PC-DPC}
@gimli_absorb_byte:
        04E9.0000: LDW     A2, [A0 + 0x30]
        04EE.0000: ADD     A2, A0
        04F0.0000: LDB     A3, [A2]
        04F2.0000: XOR     A3, A1
        04F4.0000: STB     [A2],A3
        04F6.0000: RET
@gimli_squeeze_byte:
        04F8.0000: LDW     A1, [A0 + 0x30]
        04FD.0000: ADD     A0, A1
        04FF.0000: LDB     A0, [A0]
        0501.0000: RET
@gimli_advance:
        0503.0000: ADD     A1, A0, 0x30
        0508.0000: LDW     A2, [A1]
        050A.0000: INC     A2, 1
        050C.0000: STW     [A1],A2
        050E.0000: CMP     A2, 0x10
        0512.0000: RET.NE
        0514.0000: PSH     {A1, RA-RD}
        0517.0000: FCR     @gimli
        051A.0000: POP     {A1}
        051D.0000: STW     [A1],ZERO
        051F.0000: POP     {PC-DPC}
@gimli_absorb:
        0522.0000: MOV     A2, A2
        0524.0000: RET.EQ
        0526.0000: PSH     {S0-FP, RA-RD}
        0529.0000: INC     FP, SP, 6
        052C.0000: MOV     S0, A0
        052E.0000: MOV     S1, A1
        0530.0000: MOV     S2, A2
        0532.0000: LDB     A1, [S1]
        0534.0000: INC     S1, 1
        0536.0000: MOV     A0, S0
        0538.0000: FCR     @gimli_absorb_byte
        053B.0000: MOV     A0, S0
        053D.0000: FCR     @gimli_advance
        0540.0000: INC     S2, -1
        0542.0000: BRR.NE  @gimli_hash_update+0x10 //0532.0000
        0545.0000: INC     SP, FP, -6
        0548.0000: POP     {S0-FP, PC-DPC}
@gimli_squeeze:
        054B.0000: MOV     A2, A2
        054D.0000: RET.EQ
        054F.0000: PSH     {S0-FP, RA-RD}
        0552.0000: INC     FP, SP, 6
        0555.0000: MOV     S0, A0
        0557.0000: MOV     S1, A1
        0559.0000: MOV     S2, A2
        055B.0000: ADD     A0, 0x30
        055F.0000: MOV     A1, 0xF
        0563.0000: STW     [A0],A1
        0565.0000: MOV     A0, S0
        0567.0000: FCR     @gimli_advance
        056A.0000: MOV     A0, S0
        056C.0000: FCR     @gimli_squeeze_byte
        056F.0000: STB     [S1],A0
        0571.0000: INC     S1, 1
        0573.0000: INC     S2, -1
        0575.0000: BRR.NE  @gimli_squeeze+0x1a //0565.0000
        0578.0000: INC     SP, FP, -6
        057B.0000: POP     {S0-FP, PC-DPC}
@gimli_pad:
        057E.0000: PSH     {A0, FP, RA-RD}
        0581.0000: INC     FP, SP, 2
        0584.0000: MOV     A1, 0x1
        0588.0000: FCR     @gimli_absorb_byte
        058B.0000: POP     {A0}
        058E.0000: ADD     A0, 0x2F
        0592.0000: LDB     A1, [A0]
        0594.0000: XOR     A1, 0x1
        0598.0000: STB     [A0],A1
        059A.0000: MOV     SP, FP
        059C.0000: POP     {FP, PC-DPC}
@gimli_hash_init:
        059F.0000: MOV     A1, ZERO
        05A1.0000: MOV     A2, ZERO
        05A3.0000: MOV     A3, ZERO
        05A5.0000: ADD     A0, 0x30
        05A9.0000: STW     [A0],ZERO
        05AB.0000: PSH     A0, {ZERO, A1-A3}
        05AF.0000: PSH     A0, {ZERO, A1-A3}
        05B3.0000: PSH     A0, {ZERO, A1-A3}
        05B7.0000: PSH     A0, {ZERO, A1-A3}
        05BB.0000: PSH     A0, {ZERO, A1-A3}
        05BF.0000: PSH     A0, {ZERO, A1-A3}
        05C3.0000: RET
@gimli_hash_final:
        05C5.0000: PSH     {A0-A2, FP, RA-RD}
        05C8.0000: INC     FP, SP, 6
        05CB.0000: FCR     @gimli_pad
        05CE.0000: POP     {A0-A2}
        05D1.0000: FCR     @gimli_squeeze
        05D4.0000: POP     {FP, PC-DPC}
@gimli_hash:
        05D7.0000: PSH     {A0-A3, FP, RA-RD}
        05DA.0000: INC     FP, SP, 8
        05DD.0000: SUB     SP, 0x32
        05E1.0000: MOV     A0, SP
        05E3.0000: FCR     @gimli_hash_init
        05E6.0000: ADD     A5, SP, 0x36
        05EB.0000: POP     A5, {A1-A2}
        05EF.0000: MOV     A0, SP
        05F1.0000: FCR     @gimli_absorb
        05F4.0000: ADD     A5, SP, 0x32
        05F9.0000: POP     A5, {A1-A2}
        05FD.0000: MOV     A0, SP
        05FF.0000: FCR     @gimli_hash_final
        0602.0000: MOV     SP, FP
        0604.0000: POP     {FP, PC-DPC}
@memcmp8:
        0607.0000: MOV     A3, A0
        0609.0000: LDB     A4, [A3]
        060B.0000: LDB     A5, [A1]
        060D.0000: SUB     A0, A4, A5
        0610.0000: RET.NE
        0612.0000: INC     A3, 1
        0614.0000: INC     A1, 1
        0616.0000: INC     A2, -1
        0618.0000: BRR.NE  @memcmp8+0x2 //0609.0000
        061B.0000: RET
@memcmp16:
        061D.0000: MOV     A3, A0
        061F.0000: LDW     A4, [A3]
        0621.0000: LDW     A5, [A1]
        0623.0000: SUB     A0, A4, A5
        0626.0000: RET.NE
        0628.0000: INC     A3, 2
        062A.0000: INC     A1, 2
        062C.0000: INC     A2, -2
        062E.0000: BRR.NE  @memcmp16+0x2 //061F.0000
        0631.0000: RET
@memcmp:
        0633.0000: MOV     A2, A2
        0635.0000: MOV.EQ  A0, ZERO
        0637.0000: RET.EQ
        0639.0000: MOV     A3, A0
        063B.0000: AND     A4, A3, 0x1
        0640.0000: AND     A5, A1, 0x1
        0645.0000: XOR     A4, A5
        0647.0000: BRR.NE  @memcmp8+0x2 //0609.0000
        064A.0000: MOV     A4, A4
        064C.0000: BRR.EQ  @memcmp+0x2d //0660.0000
        064F.0000: LDB     A4, [A3]
        0651.0000: LDB     A5, [A1]
        0653.0000: SUB     A0, A4, A5
        0656.0000: RET.NE
        0658.0000: INC     A3, 1
        065A.0000: INC     A1, 1
        065C.0000: INC     A2, -1
        065E.0000: RET.EQ
        0660.0000: PSH     {RA-RD}
        0663.0000: FCR     @memcmp16+0x2 //061F.0000
        0666.0000: MOV     A0, A0
        0668.0000: POP.NE  {PC-DPC}
        066B.0000: AND     ZERO, A2, 0x1
        0670.0000: POP.EQ  {PC-DPC}
        0673.0000: INC     A2, -1
        0675.0000: LDB     A4, [A3 + A2]
        0678.0000: LDB     A5, [A1 + A2]
        067B.0000: SUB     A0, A4, A5
        067E.0000: POP     {PC-DPC}

@read_line:
        0681.0000: MOV     A2, A0
        0683.0000: MOV     A0, ZERO
        0685.0000: BRR     @read_line+0x13 //0694.0000
        0688.0000: INC     A0, 1
        068A.0000: STB     [A2],A3
        068C.0000: INC     A2, 1
        068E.0000: CMP     A3, 0xA
        0692.0000: RET.EQ
        0694.0000: CMP     A0, A1
        0696.0000: RET.GE
        0698.0000: RDB     A3, (0)
        069A.0000: BRR.LT  @read_line+0x7 //0688.0000
        069D.0000: XOR     A0, 0xFFFF
        06A1.0000: RET
        
        06A3.0000: PSH     {A1, FP, RA-RD}
        06A6.0000: INC     FP, SP, 2
        06A9.0000: MOV     A1, 0x20
        06AD.0000: MOV     A2, SP
        06AF.0000: MOV     A3, 0x2
        06B3.0000: FCR     @gimli_hash
        06B6.0000: MOV     SP, FP
        06B8.0000: POP     {FP, PC-DPC}

@some_func2:
        06BB.0000: PSH     {FP, RA-RD}
        06BE.0000: MOV     FP, SP
        06C0.0000: MOV     A1, 0x6874
        06C4.0000: MOV     A2, 0x5F33
        06C8.0000: PSH     {A1-A2}
        06CB.0000: ADD     A0, PC, 0x330
        06D0.0000: MOV     A1, SP
        06D2.0000: MOV     A2, 0x4
        06D6.0000: FCR     @gimli_absorb
        06D9.0000: MOV     SP, FP
        06DB.0000: POP     {FP, PC-DPC}

@some_func1:
        06DE.0000: PSH     {S0-S1, FP, RA-RD}
        06E1.0000: INC     FP, SP, 4
        06E4.0000: ADD     S0, PC, 0x317
        06E9.0000: MOV     A0, S0
        06EB.0000: FCR     @gimli_hash_init
        06EE.0000: MOV     A0, S0
        06F0.0000: MOV     A2, 0x7B6E
        06F4.0000: MOV     A1, 0x7573
        06F8.0000: PSH     {A1-A2}
        06FB.0000: MOV     A1, SP
        06FD.0000: MOV     A2, 0x4
        0701.0000: FCR     @gimli_absorb
        0704.0000: INC     SP, 4
        0706.0000: FCR     @read_line+0x3a //06BB.0000
        0709.0000: MOV     A0, S0
        070B.0000: ADD     A1, PC, 0x235
        0710.0000: MOV     A2, 0x5
        0714.0000: FCR     @gimli_absorb
        0717.0000: ADD     S1, PC, 0x338
        071C.0000: LDB     A1, [S1]
        071E.0000: SHL     A1, 0x9
        0721.0000: BRR.LT  @read_line+0xb3 //0734.0000
        0724.0000: SRU     A1, 0x9
        0727.0000: INC     S1, 1
        0729.0000: MOV     A0, S0
        072B.0000: FCR     @gimli_absorb_byte
        072E.0000: FCR     @gimli_advance
        0731.0000: BRR     @read_line+0x9b //071C.0000
        0734.0000: RDC     A3, INSN_COUNT_LO
        0736.0000: RDC     A4, INSN_COUNT_HI
        0738.0000: ADD     A3, 0x280F
        073C.0000: ADD     A4, 0x7D52
        0740.0000: PSH     {A3-A4}
        0743.0000: MOV     A0, S0
        0745.0000: MOV     A1, SP
        0747.0000: MOV     A2, 0x4
        074B.0000: FCR     @gimli_absorb
        074E.0000: INC     SP, 4
        0750.0000: MOV     A0, S0
        0752.0000: ADD     A1, PC, 0x2DC
        0757.0000: MOV     A2, 0x20
        075B.0000: FCR     @gimli_hash_final
        075E.0000: INC     SP, FP, -4
        0761.0000: POP     {S0-S1, FP, PC-DPC}
@main:
        0764.0000: PSH     {S0, FP, RA-RD}
        0767.0000: INC     FP, SP, 2
        076A.0000: SUB     SP, 0x52
        076E.0000: FCR     @read_line+0x5d //06DE.0000
        0771.0000: MOV     S0, ZERO
        0773.0000: ADD     A0, PC, 0x188
        0778.0000: FCR     @puts
        077B.0000: MOV     A0, SP
        077D.0000: MOV     A1, 0x32
        0781.0000: FCR     @read_line
        0784.0000: INC     A0, -1
        0786.0000: WRB.NG  (0), 0xA
        078A.0000: MOV.NG  A0, 0x1
        078F.0000: FCR.NG  0xFF00
        0793.0000: CMP     A0, 0x6
        0797.0000: BRR.NE  @main+0x68 //07CC.0000
        079A.0000: MOV     A1, SP
        079C.0000: POP     A1, {A2-A4}
        07A0.0000: CMP     A2, 0x6F66
        07A4.0000: CMP.EQ  A3, 0x6772
        07A8.0000: CMP.EQ  A4, 0x746F
        07AC.0000: BRR.NE  @main+0x68 //07CC.0000
        07AF.0000: ADD     A0, PC, 0x1D4
        07B4.0000: FCR     @puts
        07B7.0000: ADD     A0, PC, 0x277
        07BC.0000: MOV     A1, 0x20
        07C0.0000: FCR     @print_hex
        07C3.0000: WRB     (0), 0x22
        07C6.0000: WRB     (0), 0xA
        07C9.0000: BRR     @main+0xf //0773.0000
        07CC.0000: MOV     A3, A0
        07CE.0000: SUB     A0, FP, 0x22
        07D3.0000: MOV     A1, 0x20
        07D7.0000: MOV     A2, SP
        07D9.0000: FCR     @gimli_hash
        07DC.0000: SUB     A0, FP, 0x22
        07E1.0000: ADD     A1, PC, 0x24D
        07E6.0000: MOV     A2, 0x20
        07EA.0000: FCR     @memcmp
        07ED.0000: CMP     A0, ZERO
        07EF.0000: BRR.NE  @main+0x99 //07FD.0000
        07F2.0000: ADD     A0, PC, 0x1AC
        07F7.0000: FCR     @puts
        07FA.0000: BRR     @main+0xb5 //0819.0000
        07FD.0000: ADD     A0, PC, 0x11C
        0802.0000: FCR     @puts
        0805.0000: INC     S0, 1
        0807.0000: CMP     S0, 0x3
        080B.0000: BRR.LT  @main+0xf //0773.0000
        080E.0000: ADD     A0, PC, 0x137
        0813.0000: FCR     @puts
        0816.0000: BRR     @main+0xf //0773.0000
        0819.0000: MOV     A0, ZERO
        081B.0000: INC     SP, FP, -2
        081E.0000: POP     {S0, FP, PC-DPC}
        0821.0000: STW     [FP],FP
        0823.0000: BRR     @main
```

There is a hash function named `gimli`. The process is implemented in `@gimli_hash`:

1. call @gimli_hash_init
2. call @gimli_absorb
3. call @gimli_hash_final

Then, it computes hash for some data, and computes hash for user input and compare the two. Therefore, we need to recover the original input of the compared hash. The code is in `some_func1`, where it calls several `@gimli_hash_init`, `@gimli_absorb`, etc. Initialy, I try to set breakpoint on `@gimli_absorb`, but it misses the bytes from `@gimli_absorb_byte`.

Therefore, we use the debugger to find the `A1` parameter of `@gimli_absorb_byte`, one byte by one byte:

```shell
$ ./runpeg --debug AccessCode.peg

EAR debugger
(dbg) b 04e9
Created breakpoint #1 at address 04E9 (X)
(dbg) c
HW breakpoint #1 hit trying to execute 1 byte at 04E9
A breakpoint was hit

Thread state:
   (ZERO)R0: 0000      (S1)R8: FD97
     (A0)R1: 0A00      (S2)R9: 0004
     (A1)R2: 0073     (FP)R10: FD90
     (A2)R3: 0004     (SP)R11: FD8A
     (A3)R4: 0000     (RA)R12: 053B
     (A4)R5: 0000     (RD)R13: 0000
     (A5)R6: EA23     (PC)R14: 04E9 //@gimli_absorb_byte+0
     (S0)R7: 0A00    (DPC)R15: 0000
FLAGS: zspcvXr

Next instructions:
@gimli_absorb_byte:
        04E9.0000: LDW     A2, [A0 + 0x30]
        04EE.0000: ADD     A2, A0
        04F0.0000: LDB     A3, [A2]
        04F2.0000: XOR     A3, A1
        04F4.0000: STB     [A2],A3
(dbg) c
HW breakpoint #1 hit trying to execute 1 byte at 04E9
A breakpoint was hit

Thread state:
   (ZERO)R0: 0000      (S1)R8: FD98
     (A0)R1: 0A00      (S2)R9: 0003
     (A1)R2: 0075     (FP)R10: FD90
     (A2)R3: 0001     (SP)R11: FD8A
     (A3)R4: 0073     (RA)R12: 053B
     (A4)R5: 0000     (RD)R13: 0000
     (A5)R6: EA23     (PC)R14: 04E9 //@gimli_absorb_byte+0
     (S0)R7: 0A00    (DPC)R15: 0000
FLAGS: zspcvXr

Next instructions:
@gimli_absorb_byte:
        04E9.0000: LDW     A2, [A0 + 0x30]
        04EE.0000: ADD     A2, A0
        04F0.0000: LDB     A3, [A2]
        04F2.0000: XOR     A3, A1
        04F4.0000: STB     [A2],A3
(dbg) c
HW breakpoint #1 hit trying to execute 1 byte at 04E9
A breakpoint was hit

Thread state:
   (ZERO)R0: 0000      (S1)R8: FD99
     (A0)R1: 0A00      (S2)R9: 0002
     (A1)R2: 006E     (FP)R10: FD90
     (A2)R3: 0002     (SP)R11: FD8A
     (A3)R4: 0075     (RA)R12: 053B
     (A4)R5: 0000     (RD)R13: 0000
     (A5)R6: EA23     (PC)R14: 04E9 //@gimli_absorb_byte+0
     (S0)R7: 0A00    (DPC)R15: 0000
FLAGS: zspcvXr

Next instructions:
@gimli_absorb_byte:
        04E9.0000: LDW     A2, [A0 + 0x30]
        04EE.0000: ADD     A2, A0
        04F0.0000: LDB     A3, [A2]
        04F2.0000: XOR     A3, A1
        04F4.0000: STB     [A2],A3
```

If we convert the values of `A1` to text, we got:

```python
>>> bytes.fromhex("73756e")
b'sun'
```

In this way, we can recover the input flag eventually: `sun{th3_fun_p4r7_15_nEAR}`.
