# Rev

```
In order to find the flag, you must first search for the flag.
```

Open the attachment in [Binary Ninja](https://binary.ninja), the main logic is:

```c
00401357            while ((int64_t)i < strlen(&input))
00401357            {
00401357                int32_t low = 0;
0040126b                int32_t high = 0xff;
0040126b                
00401281                while (true)
00401281                {
00401281                    int32_t mid = high + low;
0040128a                    int32_t mid_1 = (mid + (mid >> 0x1f)) >> 1;
0040128a                    
004012ab                    if (mid_1 == (int32_t)input[(int64_t)i])
004012ab                        break;
004012ab                    
004012e1                    if (mid_1 >= (int32_t)input[(int64_t)i])
004012e1                    {
00401310                        int32_t rax_21 = var_290_1;
00401319                        var_290_1 = rax_21 + 1;
00401321                        var_228[(int64_t)rax_21] = 0x3c;
00401332                        high = mid_1 - 1;
004012e1                    }
004012e1                    else
004012e1                    {
004012e3                        int32_t rax_17 = var_290_1;
004012ec                        var_290_1 = rax_17 + 1;
004012f4                        var_228[(int64_t)rax_17] = 0x3e;
00401305                        low = mid_1 + 1;
004012e1                    }
00401281                }
00401281                
004012ad                int32_t rax_11 = var_290_1;
004012b6                var_290_1 = rax_11 + 1;
004012be                var_228[(int64_t)rax_11] = 0x3d;
0040133d                i += 1;
00401357            }
```

Using binary search to find each byte of the input, and the result is stored in an array and compared with `target` later. We can recover each byte of the flag:

```python
target = "<><<<>>=<>>=<>>><<>=<>>><><=<><<><=<><<<><=<>>>>=<<>><=<>><<<=<<>>=<>=<><>><=<<>><<<=<>>><>=<>>><<>=<>=<><><>>=<<>><=<>><=<>><=<<>><<=<>><<>=<<>><>=<>=<<>><><=<>><>>>=<>><<><=<>=<><<>><=<<>><=<>>><<>=<>><>>>=<>=<><>><=<<>><<<=<>>><>=<>>><<>=<>=<><<<>>=<>>><>=<>><>>>=<>><<><=<<>><><=<>><>>=<<>><=<>><>>>=<<>>=<<>><><=<<>><<=<>=<><><=<<>><=<>><<<=<>>><<>=<>><<=<>><><<=<>=<><<<<=<>><>><=<>><=<<>><<<=<>>><<>=<<>><<=<<>>=<>><><<=<>><>>=<<>><>=<>>>>>="
print(len(target))

flag = bytearray()

low = 0
high = 0xff
for ch in target:
    mid = (low + high) // 2
    if ch == ">":
        low = mid + 1
    elif ch == "<":
        high = mid - 1
    else:
        flag.append(mid)
        low = 0
        high = 0xff
print(flag)
```

Flag: `FortID{3a7_Y0ur_V3gg1e5_4nd_L3rn_Y0ur_Fund4m3n741_S3arch_Alg0r17hm5}`.
