# Day 01

Disassemble the provided binary:

```asm
Disassembly of section .text:

0000000000401000 <.text>:
  401000:       48 89 e5                mov    %rsp,%rbp
  401003:       48 81 ec 00 05 00 00    sub    $0x500,%rsp
  40100a:       b8 00 00 00 00          mov    $0x0,%eax
  40100f:       bf 00 00 00 00          mov    $0x0,%edi
  401014:       48 8d b5 00 fc ff ff    lea    -0x400(%rbp),%rsi
  40101b:       ba 00 04 00 00          mov    $0x400,%edx
  401020:       0f 05                   syscall
  401022:       80 85 3f fe ff ff d4    addb   $0xd4,-0x1c1(%rbp)
  401029:       80 ad 51 fe ff ff 35    subb   $0x35,-0x1af(%rbp)
  401030:       80 ad a0 fe ff ff 38    subb   $0x38,-0x160(%rbp)
  401037:       80 ad 9c fc ff ff 91    subb   $0x91,-0x364(%rbp)
  40103e:       80 85 08 fd ff ff 92    addb   $0x92,-0x2f8(%rbp)

... omitted

  aa0dac:       80 bd 00 fc ff ff cc    cmpb   $0xcc,-0x400(%rbp)
  aa0db3:       0f 85 09 33 00 00       jne    0xaa40c2
  aa0db9:       80 bd 01 fc ff ff ca    cmpb   $0xca,-0x3ff(%rbp)
  aa0dc0:       0f 85 fc 32 00 00       jne    0xaa40c2
  aa0dc6:       80 bd 02 fc ff ff c5    cmpb   $0xc5,-0x3fe(%rbp)

... omitted

  aa402c:       48 c7 c0 01 00 00 00    mov    $0x1,%rax
  aa4033:       48 c7 c7 01 00 00 00    mov    $0x1,%rdi
  aa403a:       48 8d 35 c5 0f 00 00    lea    0xfc5(%rip),%rsi        # 0xaa5006
  aa4041:       48 c7 c2 31 00 00 00    mov    $0x31,%rdx
  aa4048:       0f 05                   syscall
```

It reads 0x400 bytes of data from stdin, do some add/sub operations and compare the result with expected values. Therefore, we can collect the assemblies to recover the correct input:

```python
values = [0] * 0x400
cmp = [0] * 0x400
# objdump -S check-list > check-list.S
for line in open("check-list.S"):
    parts = line.split()
    if len(parts) == 0 or "rbp" not in line:
        continue
    addr = int(parts[0][:-1], 16)
    if addr >= 0x401022 and addr <= 0xAA0DA5:
        value = int(parts[-1].split(",")[0].removeprefix("$"), 16)
        offset = 0x400 + int(parts[-1].split(",")[1].removesuffix("(%rbp)"), 16)
        if parts[-2] == "addb":
            values[offset] += value
        elif parts[-2] == "subb":
            values[offset] -= value
        else:
            assert False
    elif addr >= 0xAA0DAC and addr <= 0xAA4022 and "cmpb" in line:
        value = int(parts[-1].split(",")[0].removeprefix("$"), 16)
        offset = 0x400 + int(parts[-1].split(",")[1].removesuffix("(%rbp)"), 16)
        cmp[offset] = value

for i in range(0x400):
    values[i] = (cmp[i] - values[i]) % 256
open("data.bin", "wb").write(bytes(values))
print(bytes(values))
```

Get flag:

```shell
ubuntu@2025~day-01:~$ /challenge/check-list < data.bin
✨ Correct: you checked it twice, and it shows!
pwn.college{REDACTED}
```
