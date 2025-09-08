# nimrod

```
by Eth007
Description

And Cush begat Nimrod: he began to be a mighty one in the earth.
Attachments

nimrod
```

In attachment a Nim compiled program is provided. Decompile it in [Binary Ninja](https://binary.ninja/):

```c
004116c0  TM__lV8EigCDqwNSDSAg6zOZ9cw_9:
004116c0  08 00 00 00 00 00 00 00 08 00 00 00 00 00 00 40  ...............@
004116d0  43 6f 72 72 65 63 74 21 00 00 00 00 00 00 00 00  Correct!........
004116e0  TM__lV8EigCDqwNSDSAg6zOZ9cw_7:
004116e0  22 00 00 00 00 00 00 00 22 00 00 00 00 00 00 40  "......."......@
004116f0  28 f8 3e e6 3e 2f 43 0c b9 96 d1 5c d6 bf 36 d8  (.>.>/C....\..6.
00411700  20 79 0e 8e 52 21 b2 50 e3 98 b5 c9 b8 a0 88 30   y..R!.P.......0
00411710  d9 0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

00415060  void* encryptedFlag__nimrod_10 = TM__lV8EigCDqwNSDSAg6zOZ9cw_7

00410020    int64_t NimMainInner()
00410020    {
00410020        echoBinSafe(&TM__lV8EigCDqwNSDSAg6zOZ9cw_2, 1);
00410020        
00410081        if (eqeq___nimrod_69(
00410081                xorEncrypt__nimrod_46(
00410081                    nsuStrip(readLine__systemZio_271(stdin), 1, 1, 
00410081                        &TM__lV8EigCDqwNSDSAg6zOZ9cw_4), 
00410081                    0x13371337), 
00410081                encryptedFlag__nimrod_10))
004100a3            /* tailcall */
004100a3            return echoBinSafe(&TM__lV8EigCDqwNSDSAg6zOZ9cw_8, 1);
004100a3        
0041008e        /* tailcall */
0041008e        return echoBinSafe(&TM__lV8EigCDqwNSDSAg6zOZ9cw_10, 1);
00410020    }

0040fdc0    uint128_t* xorEncrypt__nimrod_46(int64_t* arg1, int32_t arg2)
0040fdc0    {
0040fdc0        if (!arg1)
0040fdd4        {
0040ffd2            keystream__nimrod_20(arg2, 0);
0040ffe1            /* tailcall */
0040ffe1            return newSeq__nimrod_29(0);
0040fdd4        }
0040fdd4        
0040fdde        uint128_t* rax = keystream__nimrod_20(arg2, *(uint64_t*)arg1);
0040fde3        uint64_t rdi_1 = *(uint64_t*)arg1;
0040fde3        
0040fded        if (rdi_1 < 0)
0040fded        {
0040fffc            raiseRangeErrorI(rdi_1, 0, 0x7fffffffffffffff);
0040fffc            /* no return */
0040fded        }

omitted.. simple xor encryption

uint128_t* keystream__nimrod_20(int32_t arg1, uint64_t arg2)
0040fce0    {
0040fce0        if (arg2 < 0)
0040fcf4        {
0040fd9f            raiseRangeErrorI(arg2, 0, 0x7fffffffffffffff);
0040fd9f            /* no return */
0040fcf4        }
0040fcf4        
0040fcfa        int32_t rbx = arg1;
0040fcff        uint128_t* result;
0040fcff        int32_t rcx;
0040fcff        int64_t rdx;
0040fcff        result = newSeq__nimrod_29(arg2);
0040fcff        
0040fd0a        if (arg2)
0040fd0a        {
0040fd0c            uint64_t rbp_1 = 0;
0040fd0c            
0040fd11            if (!result)
0040fd11            {
0040fd74                raiseIndexError2(0, -1, rdx, rcx);
0040fd74                /* no return */
0040fd11            }
0040fd11            
0040fd4a            do
0040fd4a            {
0040fd1e                int64_t rsi = *(uint64_t*)result;
0040fd22                rbx = rbx * 0x19660d + 0x3c6ef35f;
0040fd22                
0040fd2b                if (rsi <= rbp_1)
0040fd2b                {
0040fd34                    raiseIndexError2(rbp_1, rsi - 1, rdx, rcx);
0040fd34                    /* no return */
0040fd2b                }
0040fd2b                
0040fd3e                *(uint8_t*)((char*)result + rbp_1 + 0x10) = (char)(rbx >> 0x10);
0040fd43                rbp_1 += 1;
0040fd4a            } while (arg2 > rbp_1);
0040fd0a        }
0040fd0a        
0040fd59        return result;
0040fce0    }

```

So essentiall the program does:

1. read from inputt
2. generate a keystream using 0x13371337
3. xor input and keystrem
4. compare it with the encrypted flag

From the code, we can see that the Nim arrays has it sized stored at offset 0x00, and its data begins from 0x10. So we just compute the keystream and xor it with the encrypted flag in python:

```python
key = 0x13371337
encrypted = "2200000000000000220000000000004028f83ee63e2f430cb996d15cd6bf36d820790e8e5221b250e398b5c9b8a08830d90a0000000000000000000000000000"
for ch in bytes.fromhex(encrypted)[0x10:]:
    key = key * 0x19660d + 0x3c6ef35f
    key %= 2 ** 32
    print(chr(ch ^ ((key >> 0x10) & 0xFF)), end="")
```

Get flag: `ictf{a_mighty_hunter_bfc16cce9dc8}`.
