# secure exam browser

```
I love academic misconduct
```

Running the program directly will fail for all possible inputs:

```
Welcome to Secure Exam Browser
Enter Password: 123456
ERR: another process is running!
```

The problem lies in the `op` function. We patch the caller function to skip over it:

```
.text:000000000000473C ; =============== S U B R O U T I N E =======================================
.text:000000000000473C
.text:000000000000473C
.text:000000000000473C ; bool obf::bool_functor<`anonymous namespace'::decode_flag(std::string const&)::{lambda(void)#11}::operator() const(void)::{lambda(void)#3}>::run()
.text:000000000000473C _ZN3obf12bool_functorIZZN12_GLOBAL__N_111decode_flagERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEENKUlvE9_clEvEUlvE1_E3runEv proc near
.text:000000000000473C                                         ; DATA XREF: .data.rel.ro:0000000000008988↓o
.text:000000000000473C ; __unwind {
.text:000000000000473C                 endbr64
.text:0000000000004740                 sub     rsp, 8
.text:0000000000004744                 call    _Z2opv          ; op(void)
.text:0000000000004749                 test    eax, eax
.text:000000000000474B                 setnz   al
.text:000000000000474E                 add     rsp, 8
.text:0000000000004752                 retn
.text:0000000000004752 ; } // starts at 473C
.text:0000000000004752 _ZN3obf12bool_functorIZZN12_GLOBAL__N_111decode_flagERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEENKUlvE9_clEvEUlvE1_E3runEv endp
```

Replace the `sub rsp, 8` instruction with `ret`. Then, we can execute it correctly:

```shell
Welcome to Secure Exam Browser
Enter Password: 123456
Incorrect password!
```

Next, we find the `Incorrect password!` string and its logic surround (somehow the logic is hidden from the decompiler of IDA):

```
.text:00000000000050D7                 mov     rdx, [rsp+58h+n] ; n
.text:00000000000050DC                 cmp     rdx, [rsp+58h+var_30]
.text:00000000000050E1                 jz      short loc_50F8
.text:00000000000050E3
.text:00000000000050E3 loc_50E3:                               ; CODE XREF: main+B1↓j
.text:00000000000050E3                 lea     rsi, aIncorrectPassw ; "Incorrect password!\n"
.text:00000000000050EA                 lea     rdi, _ZSt4cout@@GLIBCXX_3_4
.text:00000000000050F1 ;   try {
.text:00000000000050F1                 call    __ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc ; std::operator<<<std::char_traits<char>>(std::ostream &,char const*)
.text:00000000000050F6                 jmp     short loc_5135
.text:00000000000050F8 ; ---------------------------------------------------------------------------
.text:00000000000050F8
.text:00000000000050F8 loc_50F8:                               ; CODE XREF: main+85↑j
.text:00000000000050F8                 mov     rsi, [rsp+58h+s2] ; s2
.text:00000000000050FD                 mov     rdi, [rsp+58h+s1] ; s1
.text:0000000000005101                 test    rdx, rdx
.text:0000000000005104                 jz      short loc_510F
.text:0000000000005106                 call    _memcmp
.text:000000000000510B                 test    eax, eax
.text:000000000000510D                 jnz     short loc_50E3
```

Using pwndbg, we set a breakpoint at `0x50DC` which is `main+128`, it shows the expected length of input:

```
───────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────────────────────────────────────────────
 ► 0x5555555590dc <main+128>    cmp    rdx, qword ptr [rsp + 0x28]     0x6 - 0x2c     EFLAGS => 0x293 [ CF pf AF zf SF IF df of ac ]
b+ 0x5555555590e1 <main+133>  ✘ je     main+156                    <main+156>

   0x5555555590e3 <main+135>    lea    rsi, [rip + 0xfc0]              RSI => 0x55555555a0aa ◂— 'Incorrect password!\n'
```

So the flag length is `0x2c`. Input 44 `A` and step through memcmp:

```
───────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────────────────────────────────────────────
b+ 0x5555555590e1 <main+133>  ✔ je     main+156                    <main+156>
    ↓
   0x5555555590f8 <main+156>    mov    rsi, qword ptr [rsp + 0x20]     RSI, [0x7fffffffe440] => 0x555555570c20 ◂— "K17{i_heard_that_it's_impossible_to_re_c++!}"
   0x5555555590fd <main+161>    mov    rdi, qword ptr [rsp]            RDI, [0x7fffffffe420] => 0x555555570b70 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
   0x555555559101 <main+165>    test   rdx, rdx                        0x2c & 0x2c     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
   0x555555559104 <main+168>  ✘ je     main+179                    <main+179>

 ► 0x555555559106 <main+170>    call   memcmp@plt                  <memcmp@plt>
        s1: 0x555555570b70 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        s2: 0x555555570c20 ◂— "K17{i_heard_that_it's_impossible_to_re_c++!}"
        n: 0x2c

   0x55555555910b <main+175>    test   eax, eax
   0x55555555910d <main+177>    jne    main+135                    <main+135>
```

The flag is `K17{i_heard_that_it's_impossible_to_re_c++!}`.
