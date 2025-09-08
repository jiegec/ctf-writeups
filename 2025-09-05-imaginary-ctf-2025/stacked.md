# stacked

```
by Minerva-007.
Description

Return oriented programming is one of the paradigms of all time. The garbled output is 94 7 d4 64 7 54 63 24 ad 98 45 72 35 hex.
```

Decompile the attachment in [Binary Ninja](https://binary.ninja):

```c
00401169    uint64_t eor(uint8_t arg1) __pure

00401169    {
00401169        return (uint64_t)arg1 ^ 0x69;
00401169    }

00401169    }


0040117f    uint64_t inc(uint8_t arg1)

0040117f    {
0040117f        flag[(int64_t)globalvar] = arg1;
004011b0        globalvar += 1;
004011ce        return (uint64_t)flag[(int64_t)globalvar];
0040117f    }

004011cf    uint64_t rtr(uint8_t arg1) __pure

004011cf    {
004011cf        uint32_t rax_1;
004011e0        (uint8_t)rax_1 = arg1 >> 1;
004011ee        return (uint64_t)((uint32_t)arg1 << 7) | (uint64_t)rax_1;
004011cf    }

004011cf    }


004011ef    uint64_t off(uint8_t arg1) __pure

004011ef    {
004011ef        return (uint64_t)((uint32_t)arg1 + 0xf);
004011ef    }

00401205    int32_t main(int32_t argc, char** argv, char** envp)

00401205    {
00401205        uint8_t rax_61 = rtr(inc(rtr(eor(rtr(inc(rtr(off(rtr(inc(eor(eor(eor(inc(eor(rtr(
00401205            rtr(inc(rtr(off(rtr(inc(eor(eor(eor(inc(rtr(eor(off(flag[(int64_t)
00401205            globalvar])))))))))))))))))))))))))))));
004013e5        uint8_t rax_93 = rtr(inc(rtr(off(off(inc(rtr(eor(eor(inc(eor(off(rtr(inc(eor(rtr(
004013e5            rax_61))))))))))))))));
00401453        inc(off(eor(off(inc(rtr(off(eor(inc(eor(rtr(rax_93)))))))))));
00401453        
00401492        for (int32_t i = 0; i <= 0xc; i += 1)
00401492            printf("%x ", (uint64_t)flag[(int64_t)i], "REDACTEDREDAC");
00401492        
00401499        putchar(0xa);
004014a4        return 0;
00401205    }

```

The output is given in the challenge description. We need to reverse the steps to get the initial flag input:

1. Convert decompiled code to a list of operations
2. Reverse the operations to find the flag

```python
result = bytes.fromhex("9407d46407546324ad98457235")

operations = """
uint8_t rax_61 = rtr(inc(rtr(eor(rtr(inc(rtr(off(rtr(inc(eor(eor(eor(inc(eor(rtr(rtr(inc(rtr(off(rtr(inc(eor(eor(eor(inc(rtr(eor(off(flag[(int64_t)globalvar])))))))))))))))))))))))))))));
uint8_t rax_93 = rtr(inc(rtr(off(off(inc(rtr(eor(eor(inc(eor(off(rtr(inc(eor(rtr(rax_61))))))))))))))));
inc(off(eor(off(inc(rtr(off(eor(inc(eor(rtr(rax_93)))))))))));
"""

ops = ["inc", "off", "eor", "rtr"]
order = []

for line in reversed(operations.splitlines()):
    for part in line.split("("):
        #print(part, part[-3:], part[-3:] in ops)
        part = part[-3:]
        if part in ops:
            order.append(part)
print(order)

i = order.count("inc")
# apply ops in reverse
temp = 0
buffer = [0] * (i + 1)
for op in order:
    print(i, op, hex(temp))
    if op == "inc":
        buffer[i] = temp
        i = i - 1
        if i < len(result):
            temp = result[i]
    elif op == "off":
        temp = (temp - 0xF + 0x100) % 0x100
    elif op == "eor":
        temp = temp ^ 0x69
    elif op == "rtr":
        temp = ((temp << 1) & 0xFF) | (temp >> 7)
buffer[0] = temp
print(buffer)
print(bytes(buffer[:-1]))

# verify
i = 0
temp = buffer[0]
for op in reversed(order):
    if op == "inc":
        print(hex(temp) + " ", end="")
        i = i + 1
        temp = buffer[i]
    elif op == "off":
        temp = (temp + 0xF) % 0x100
    elif op == "eor":
        temp = temp ^ 0x69
    elif op == "rtr":
        temp = ((temp << 7) & 0xFF) | (temp >> 1)
```

Get flag: `ictf{1n54n3_5k1ll2}`.
