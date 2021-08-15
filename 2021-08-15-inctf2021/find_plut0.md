# find_plut0

给了一个 exe，需要逆向，得到的源代码大概如下：

```cpp
undefined8 main(void)
{
  size_t sVar1;
  
  FUN_00100b0a();
  puts("Hello there , i lost my dog pluto :(\nHelp me call him out please !!");
  __isoc99_scanf(&%s,0x302100);
  sVar1 = strlen(buffer3 + 0x20);
  if (sVar1 != 0x1e) {
    FUN_001008aa();
  }
  buffer2[0] = (int)buffer3[33] + buffer3[32] + -0x32;
  buffer2[1] = (int)buffer3[34] + buffer3[33] + -100;
  buffer2[2] = (int)buffer3[34] << 2;
  buffer2[3] = SEXT14((char)(buffer3[35] ^ 0x46));
  buffer2[4] = 0x24 - ((int)(char)buffer3[35] - (int)buffer3[36]);
  buffer2[6] = (int)buffer3[37] * (int)(char)buffer3[38] + 99;
  buffer2[7] = SEXT14((char)(buffer3[39] ^ buffer3[38]));
  buffer2[8] = (int)buffer3[40] ^ (int)(char)buffer3[39] + 0x2dU;
  buffer2[9] = ((int)buffer3[41] & 0x37U) - 3;
  buffer2[11] = (int)buffer3[43] - 0x26;
  buffer2[12] = ((char)(buffer3[38] ^ buffer3[44]) + 4) * 4;
  buffer2[5] = (int)buffer3[53] - (int)buffer3[36] ^ 0x30;
  buffer2[13] = ((int)buffer3[45] - (int)buffer3[46]) - 1;
  buffer2[10] = ((int)buffer3[49] - (int)buffer3[48]) + 0x52;
  buffer2[16] = (char)(buffer3[51] ^ buffer3[50]) * 6 + 0x36;
  buffer2[17] = (int)(char)(buffer3[52] ^ 0x73) + buffer3[53] + 0x31;
  buffer2[14] = SEXT14(buffer3[54]);
  buffer2[18] = SEXT14((char)(buffer3[55] ^ 0x42));
  buffer2[15] = (int)buffer3[58] + 5;
  buffer2[19] = ((int)buffer3[57] - (int)(buffer3[58] / '\x02')) - 0x37;
  buffer2[20] = buffer3[59] * 4 - (buffer3[60] + 0x80);
  buffer2[21] = (int)buffer3[61] - 0x20;
  FUN_001008d0(buffer2);
  return 0;
}


void FUN_001008d0(undefined4 *param_1)

{
  char cVar1;
  int iVar2;
  
  buffer3[0] = ((byte)*param_1 ^ 2) - 0x1f;
  cVar1 = (char)((int)param_1[1] >> 0x1f);
  buffer3[1] = ((byte)*param_1 ^ ((char)param_1[1] - cVar1 & 1U) + cVar1) - 0x1d;
  buffer3[2] = (byte)(param_1[1] << 2) ^ 0x97;
  buffer3[4] = ((byte)param_1[3] ^ 0x4d) + 7;
  buffer3[5] = (char)(param_1[5] << 2) + -1;
  buffer3[3] = (char)param_1[4] + 't';
  buffer3[6] = (char)param_1[6] + '\x15';
  buffer3[7] = (char)param_1[7] + -0x14;
  buffer3[8] = (byte)param_1[8] ^ 99;
  buffer3[9] = (((byte)param_1[10] ^ 3) - (char)param_1[8]) + '6';
  buffer3[10] = (byte)param_1[9] ^ 0x42;
  buffer3[11] = (byte)param_1[0xc] ^ 0xb3;
  buffer3[12] = (char)param_1[0xd] + 0x12U ^ 0x1a;
  buffer3[13] = (char)param_1[0xe] + -7;
  buffer3[15] = (byte)param_1[0x11] ^ 0xe5;
  buffer3[16] = ((byte)param_1[0x12] & 0x36) + 0x35;
  buffer3[14] = (byte)param_1[0x13] ^ 0x34;
  buffer3[17] = (byte)param_1[0x14] ^ 0xfd;
  buffer3[18] = (byte)((int)param_1[0x14] >> ((byte)param_1[0x15] & 0x1f)) ^ 0x1c;
  iVar2 = strcmp(buffer3,s_inctf{U_Sur3_m4Te?}_00302010);
  if (iVar2 == 0) {
    puts(
        "\n ................\n |w00ff w00ff!! |\n  \'\'\'\'\'V\'\'\'\'\'\'\'\' \n \n     .~````~. \n  .,/        \\,. \n (  | (0  0) |  )\n (  |  ____  |  )\n (_/|  \\__/  |\\_)\n     \\__/\\__/\n      \'-..-\'  \n"
        );
    puts("\nYeey you found him !!!!\n Grab your reward from nc!");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  FUN_001008aa();
  return;
}
```

大意就是输入一段字符串，然后经过一系列计算以后，将结果与预期字符串比对。一种办法是用 z3 实现，但是这里格式转换什么的比较麻烦，我就用 fuzz 的方法求解：

```cpp
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t byte;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size != 30)
    return 0;
  char *buffer = (char *)Data;
  int buffer2[22] = {};
  buffer2[0] = (int)buffer[1] + buffer[0] + -0x32;
  buffer2[1] = (int)buffer[2] + buffer[1] + -100;
  buffer2[2] = (int)buffer[2] << 2;
  buffer2[3] = ((char)(buffer[3] ^ 0x46));
  buffer2[4] = 0x24 - ((int)(char)buffer[3] - (int)buffer[4]);
  buffer2[6] = (int)buffer[5] * (int)(char)buffer[6] + 99;
  buffer2[7] = ((char)(buffer[7] ^ buffer[6]));
  buffer2[8] = (int)buffer[8] ^ (int)(char)buffer[7] + 0x2dU;
  buffer2[9] = ((int)buffer[9] & 0x37U) - 3;
  buffer2[11] = (int)buffer[11] - 0x26;
  buffer2[12] = ((char)(buffer[6] ^ buffer[12]) + 4) * 4;
  buffer2[5] = (int)buffer[21] - (int)buffer[4] ^ 0x30;
  buffer2[13] = ((int)buffer[13] - (int)buffer[14]) - 1;
  buffer2[10] = ((int)buffer[17] - (int)buffer[16]) + 0x52;
  buffer2[16] = (char)(buffer[19] ^ buffer[18]) * 6 + 0x36;
  buffer2[17] = (int)(char)(buffer[20] ^ 0x73) + buffer[21] + 0x31;
  buffer2[14] = (buffer[22]);
  buffer2[18] = ((char)(buffer[23] ^ 0x42));
  buffer2[15] = (int)buffer[26] + 5;
  buffer2[19] = ((int)buffer[25] - (int)(buffer[26] / '\x02')) - 0x37;
  buffer2[20] = buffer[27] * 4 - (buffer[28] + 0x80);
  buffer2[21] = (int)buffer[29] - 0x20;

  char cVar1;
  int iVar2;

  char buffer3[19] = {};
  int *param_1 = buffer2;
  buffer3[0] = ((byte)*param_1 ^ 2) - 0x1f;
  cVar1 = (char)((int)param_1[1] >> 0x1f);
  buffer3[1] =
      ((byte)*param_1 ^ ((char)param_1[1] - cVar1 & 1U) + cVar1) - 0x1d;
  buffer3[2] = (byte)(param_1[1] << 2) ^ 0x97;
  buffer3[4] = ((byte)param_1[3] ^ 0x4d) + 7;
  buffer3[5] = (char)(param_1[5] << 2) + -1;
  buffer3[3] = (char)param_1[4] + 't';
  buffer3[6] = (char)param_1[6] + '\x15';
  buffer3[7] = (char)param_1[7] + -0x14;
  buffer3[8] = (byte)param_1[8] ^ 99;
  buffer3[9] = (((byte)param_1[10] ^ 3) - (char)param_1[8]) + '6';
  buffer3[10] = (byte)param_1[9] ^ 0x42;
  buffer3[11] = (byte)param_1[0xc] ^ 0xb3;
  buffer3[12] = (char)param_1[0xd] + 0x12U ^ 0x1a;
  buffer3[13] = (char)param_1[0xe] + -7;
  buffer3[15] = (byte)param_1[0x11] ^ 0xe5;
  buffer3[16] = ((byte)param_1[0x12] & 0x36) + 0x35;
  buffer3[14] = (byte)param_1[0x13] ^ 0x34;
  buffer3[17] = (byte)param_1[0x14] ^ 0xfd;
  buffer3[18] =
      (byte)((int)param_1[0x14] >> ((byte)param_1[0x15] & 0x1f)) ^ 0x1c;
  char target[] = "inctf{U_Sur3_m4Te?}";
  if (buffer3[0] != target[0]) {
    return 0;
  }
  if (buffer3[1] != target[1]) {
    return 0;
  }
  if (buffer3[2] != target[2]) {
    return 0;
  }
  if (buffer3[3] != target[3]) {
    return 0;
  }
  if (buffer3[4] != target[4]) {
    return 0;
  }
  if (buffer3[5] != target[5]) {
    return 0;
  }
  if (buffer3[6] != target[6]) {
    return 0;
  }
  if (buffer3[7] != target[7]) {
    return 0;
  }
  if (buffer3[8] != target[8]) {
    return 0;
  }
  if (buffer3[9] != target[9]) {
    return 0;
  }
  if (buffer3[10] != target[10]) {
    return 0;
  }
  if (buffer3[11] != target[11]) {
    return 0;
  }
  if (buffer3[12] != target[12]) {
    return 0;
  }
  if (buffer3[13] != target[13]) {
    return 0;
  }
  if (buffer3[14] != target[14]) {
    return 0;
  }
  if (buffer3[15] != target[15]) {
    return 0;
  }
  if (buffer3[16] != target[16]) {
    return 0;
  }
  if (buffer3[17] != target[17]) {
    return 0;
  }
  if (buffer3[18] != target[18]) {
    return 0;
  }
  __builtin_trap();
  return iVar2;
}
```

拆分成很多分支是为了让 fuzzer 更容易通过走过的分支不同找到匹配更长前缀的输入，这里也许有更好的写法。然后编译运行：

```shell
$ clang++ -fsanitize=address,fuzzer fuzzer.cpp -o fuzzer
$ mkdir -p corpus
$ ./fuzzer -max_len=3 corpus/
NFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3291888671
INFO: Loaded 1 modules   (22 inline 8-bit counters): 22 [0x55afe826cc00, 0x55afe826cc16), 
INFO: Loaded 1 PC tables (22 PCs): 22 [0x55afe826cc18,0x55afe826cd78), 
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 2 ft: 2 corp: 1/1b exec/s: 0 rss: 30Mb
#2947   NEW    cov: 3 ft: 3 corp: 2/31b lim: 30 exec/s: 0 rss: 30Mb L: 30/30 MS: 5 CrossOver-EraseBytes-ChangeBinInt-ChangeByte-InsertRepeatedBytes-
#147578 NEW    cov: 4 ft: 4 corp: 3/61b lim: 30 exec/s: 0 rss: 38Mb L: 30/30 MS: 1 InsertRepeatedBytes-
#148446 NEW    cov: 5 ft: 5 corp: 4/91b lim: 30 exec/s: 0 rss: 38Mb L: 30/30 MS: 3 ChangeBinInt-CrossOver-ChangeByte-
#298952 NEW    cov: 6 ft: 6 corp: 5/121b lim: 30 exec/s: 0 rss: 47Mb L: 30/30 MS: 1 ChangeByte-
#316988 NEW    cov: 7 ft: 7 corp: 6/151b lim: 30 exec/s: 0 rss: 48Mb L: 30/30 MS: 1 ChangeByte-
#4194304        pulse  cov: 7 ft: 7 corp: 6/151b lim: 30 exec/s: 1398101 rss: 276Mb
#8388608        pulse  cov: 7 ft: 7 corp: 6/151b lim: 30 exec/s: 1398101 rss: 517Mb
#16777216       pulse  cov: 7 ft: 7 corp: 6/151b lim: 30 exec/s: 1290555 rss: 519Mb
#18632135       NEW    cov: 8 ft: 8 corp: 7/181b lim: 30 exec/s: 1330866 rss: 519Mb L: 30/30 MS: 2 ChangeBinInt-ChangeByte-
#18643672       NEW    cov: 9 ft: 9 corp: 8/211b lim: 30 exec/s: 1331690 rss: 519Mb L: 30/30 MS: 2 CopyPart-ChangeBit-
#24568052       NEW    cov: 10 ft: 10 corp: 9/241b lim: 30 exec/s: 1293055 rss: 523Mb L: 30/30 MS: 5 ChangeBit-ChangeByte-ChangeByte-ChangeBinInt-ChangeByte-
#24757679       NEW    cov: 11 ft: 11 corp: 10/271b lim: 30 exec/s: 1303035 rss: 523Mb L: 30/30 MS: 2 ChangeBit-ChangeByte-
#26020842       NEW    cov: 12 ft: 12 corp: 11/301b lim: 30 exec/s: 1301042 rss: 523Mb L: 30/30 MS: 3 CopyPart-ChangeByte-ChangeByte-
#26117144       NEW    cov: 13 ft: 13 corp: 12/331b lim: 30 exec/s: 1305857 rss: 523Mb L: 30/30 MS: 2 ChangeByte-ChangeByte-
#26142896       NEW    cov: 14 ft: 14 corp: 13/361b lim: 30 exec/s: 1307144 rss: 523Mb L: 30/30 MS: 2 ChangeBit-ChangeASCIIInt-
#26165012       NEW    cov: 15 ft: 15 corp: 14/391b lim: 30 exec/s: 1308250 rss: 523Mb L: 30/30 MS: 1 ShuffleBytes-
#26773498       NEW    cov: 16 ft: 16 corp: 15/421b lim: 30 exec/s: 1338674 rss: 525Mb L: 30/30 MS: 1 ChangeByte-
#29737219       NEW    cov: 17 ft: 17 corp: 16/451b lim: 30 exec/s: 1292922 rss: 527Mb L: 30/30 MS: 1 ChangeByte-
#29758031       NEW    cov: 18 ft: 18 corp: 17/481b lim: 30 exec/s: 1293827 rss: 527Mb L: 30/30 MS: 2 ChangeBit-ChangeBit-
#30749787       NEW    cov: 19 ft: 19 corp: 18/511b lim: 30 exec/s: 1281241 rss: 527Mb L: 30/30 MS: 1 ChangeByte-
#30840239       NEW    cov: 20 ft: 20 corp: 19/541b lim: 30 exec/s: 1285009 rss: 527Mb L: 30/30 MS: 2 CopyPart-ChangeByte-
#33075575       NEW    cov: 21 ft: 21 corp: 20/571b lim: 30 exec/s: 1272137 rss: 527Mb L: 30/30 MS: 1 CMP- DE: "\x01\xc2"-
==1616955== ERROR: libFuzzer: deadly signal
    #0 0x55afe81fb9ab in __sanitizer_print_stack_trace (/home/jiegec/inctf2021/find_plut0/fuzzer+0x11d9ab)
    #1 0x55afe81495d1 in fuzzer::PrintStackTrace() (/home/jiegec/inctf2021/find_plut0/fuzzer+0x6b5d1)
    #2 0x55afe8128de9 in fuzzer::Fuzzer::CrashCallback() (.part.0) (/home/jiegec/inctf2021/find_plut0/fuzzer+0x4ade9)
    #3 0x55afe8128ea7 in fuzzer::Fuzzer::StaticCrashSignalCallback() (/home/jiegec/inctf2021/find_plut0/fuzzer+0x4aea7)
    #4 0x7f35f823286f  (/usr/lib/libpthread.so.0+0x1386f)
    #5 0x55afe822cb6e in LLVMFuzzerTestOneInput (/home/jiegec/inctf2021/find_plut0/fuzzer+0x14eb6e)
    #6 0x55afe8129adc in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/home/jiegec/inctf2021/find_plut0/fuzzer+0x4badc)
    #7 0x55afe812b7b0 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) (/home/jiegec/inctf2021/find_plut0/fuzzer+0x4d7b0)
    #8 0x55afe812c54c in fuzzer::Fuzzer::MutateAndTestOne() (/home/jiegec/inctf2021/find_plut0/fuzzer+0x4e54c)
    #9 0x55afe812e027 in fuzzer::Fuzzer::Loop(std::vector<fuzzer::SizedFile, fuzzer::fuzzer_allocator<fuzzer::SizedFile> >&) (/home/jiegec/inctf2021/find_plut0/fuzzer+0x50027)
    #10 0x55afe8114ddb in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/home/jiegec/inctf2021/find_plut0/fuzzer+0x36ddb)
    #11 0x55afe8104293 in main (/home/jiegec/inctf2021/find_plut0/fuzzer+0x26293)
    #12 0x7f35f804bb24 in __libc_start_main (/usr/lib/libc.so.6+0x27b24)
    #13 0x55afe81042ed in _start (/home/jiegec/inctf2021/find_plut0/fuzzer+0x262ed)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
MS: 1 ChangeBit-; base unit: 6dbb3c5ffc60d3db0d20a0d1010a5c26453b17f9
0x5e,0x5e,0x43,0x54,0x30,0xff,0x23,0x50,0x4d,0x33,0x26,0x9c,0xff,0x5e,0x2a,0xa1,0xa1,0xbb,0x5e,0x5e,0x52,0x5f,0x74,0x7a,0x5e,0x5e,0x4e,0x41,0xc2,0xa1,
^^CT0\xff#PM3&\x9c\xff^*\xa1\xa1\xbb^^R_tz^^NA\xc2\xa1
artifact_prefix='./'; Test unit written to ./crash-d4be3aa51be75ffc7155e25b8e79dc10df0e7b6d
Base64: Xl5DVDD/I1BNMyac/14qoaG7Xl5SX3R6Xl5OQcKh
```

可以看到结果已经输出了。最后再加个回车，发送到服务器就可以拿到 flag：

```shell
$ xxd ./crash-d4be3aa51be75ffc7155e25b8e79dc10df0e7b6d 
00000000: 5e5e 4354 30ff 2350 4d33 269c ff5e 2aa1  ^^CT0.#PM3&..^*.
00000010: a1bb 5e5e 525f 747a 5e5e 4e41 c2a1       ..^^R_tz^^NA..
$ echo "" >> ./crash-d4be3aa51be75ffc7155e25b8e79dc10df0e7b6d
$ cat ./crash-d4be3aa51be75ffc7155e25b8e79dc10df0e7b6d | nc 34.94.181.140 4205
Hello there , i lost my dog pluto :(
Help me call him out please !!

 ................
 |w00ff w00ff!! |
  '''''V'''''''' 
 
     .~````~. 
  .,/        \,. 
 (  | (0  0) |  )
 (  |  ____  |  )
 (_/|  \__/  |\_)
     \__/\__/
      '-..-'  


inctf{PluT0_C0m3_&_g3t_y0uR_tr3aToz!}⏎
```

另外，还有其他正确的解：

```shell
$ xxd ./crash-cb2878d8e63e7546ad1ae8790e26732f7d92721
00000000: 4b71 7054 3027 5b28 65b3 9786 87d9 a58e  KqpT0'[(e.......
00000010: d5ef b7fa 121f 743a ef13 b7bf ba41 0a    ......t:.....A.
$ xxd ./crash-cda16159f443200b5c8b241ac810ca44851f3761 
00000000: 4b71 7054 3027 5b28 65b3 9786 87d9 a58e  KqpT0'[(e.......
00000010: d5ef b7fa 121f 743a ef13 b7bf ba21       ......t:.....!
```

P.S. 可能会出现一些不合法的答案：

```shell
# len=11
$ xxd ./crash-10346f4b2bb6482f0004f794033573f20fdab4a9
00000000: 5e5e 4354 30bd a1d2 cf3b 0100 3d33 ff00  ^^CT0....;..=3..
00000010: 001a 1f00 121f 74f3 00f8 8141 c241       ......t....A.A
# len=10
$ xxd ./crash-6e515694c0e594941a6518441538cfbcf590f7e3
00000000: 4a72 6f54 3083 1f6c a933 0000 03b4 8080  JroT0..l.3......
00000010: 5b75 0080 121f 743b fff7 80c0 be81       [u....t;......
```

这和 scanf %s 的行为有关：中间不能有空白字符（iswspace 函数，例如 0x09-0x0d 0x20）。