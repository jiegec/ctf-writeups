# Beshcan

```
Your task is to shatter Beshcan, an irreversible algorithm concealed within.
```

The attachment is a static riscv64 binary. However, if we run it using qemu-riscv64 or on a latest RISC-V Linux machine, it always fails to find the flag file. Using strace, it turns out that it uses the legacy 1024 for `open` syscall:

```shell
qemu-riscv64 -strace ./beshcan
3176468 brk(NULL) = 0x00000000000ce000
3176468 brk(0x00000000000ce4b0) = 0x00000000000ce4b0
3176468 brk(0x00000000000cf000) = 0x00000000000cf000
3176468 Unknown syscall 1024
3176468 fstat(1,0x00007fa509a4e080) = 0
3176468 fstat(1,0x00007fa509a4e000) = 0
3176468 write(1,0xce780,19)Missing flag file!
 = 19
3176468 close(0) = 0
3176468 close(1) = 0
3176468 close(2)
```

We modified qemu source to add the missing mapping:

```diff
diff --git a/linux-user/riscv/syscall.tbl b/linux-user/riscv/syscall.tbl
index 845e24eb37..ab470de3ad 100644
--- a/linux-user/riscv/syscall.tbl
+++ b/linux-user/riscv/syscall.tbl
@@ -403,3 +403,4 @@
 460    common  lsm_set_self_attr               sys_lsm_set_self_attr
 461    common  lsm_list_modules                sys_lsm_list_modules
 462    common  mseal                           sys_mseal
+1024   common  open                            sys_open
```

Now we have a qemu version that can run the binary. Then, by some manual testing, we find that the program:

1. reads each byte from `flag` file
2. maps each byte to two bytes using a fixed mapping, and the mapped bytes are swapped if the index is odd
3. writes mapped files to `secret.enc`

So we can simply enumerate `0-255` values to find their fixed mapping. Then, we reverse the mapping to get the flag image:

```python
import string
import os

# find mapping for all characters
mapping = dict()
for ch in range(0, 256):
    open("flag", "wb").write(bytes([ch] * 2))
    os.system("~/qemu/build/qemu-riscv64 ./beshcan")
    data = open("secret.enc", "rb").read()
    print(ch, data)
    mapping[data[0:2]] = ch
    mapping[data[2:4]] = ch

# this is the original secret.enc file
enc = open("secret.enc.bak", "rb").read()
plain = bytearray()
for i in range(0, len(enc), 2):
    plain.append(mapping[enc[i : i + 2]])
open("flag.jpg", "wb").write(plain)
```

![](./beshcan.png)
 
Flag: `ASIS{7H1S_iZ_jUsT_0n3_raNdOm_5hUfF1E!}`.
