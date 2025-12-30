# HyperJump

合作者：@9vvert

```
组织使用了一个定制的虚拟机程序来保护他们的秘密。你需要找到能够通过验证的口令。有时候，最复杂的迷宫也有它的规律...
The organization used a customized virtual machine program to protect their secrets. You need to find a password that can be verified. Sometimes, even the most complex maze has its own patterns ..
```

题目给了一个二进制需要逆向，通过标准输入读取 flag，然后打印比较是否成功。经过逆向，可以发现 flag 一共有 24 字节，在循环中，每次循环对输入的一个字节进行一定的操作，然后判断是否成功。一般对于这种检查前缀的题目，思路是：

1. 给定前缀，通过某种方法得到程序匹配成功的前缀长度
2. 实现深度优先搜索，找到符合要求的输入，即可得 flag

为了得到程序匹配成功的前缀长度，传统方法是利用 QEMU 进行侧信道测量，例如 [Instruction Stomp](https://github.com/ChrisTheCoolHut/Instruction-Stomp)，但在这里，@9vvert 提出了一个更巧妙的办法：当循环中比较失败的时候，把循环的迭代次数寄存器（在这里是 r15）作为 main 的返回值，那么就可以直接通过 exit code 来判断匹配的前缀长度了。当然了，原来的二进制并没有这个功能，所以需要进行一些 patch：

```diff
--- hyperjump_orig.S
+++ hyperjump.S
@@ -1,5 +1,5 @@

-hyperjump_orig:     file format elf64-x86-64
+hyperjump:     file format elf64-x86-64


 Disassembly of section .init:
@@ -288,7 +288,9 @@
     143f:      c3                      ret
     1440:      48 8d 3d 14 42 00 00    lea    0x4214(%rip),%rdi        # 565b <__cxa_finalize@plt+0x457b>
     1447:      e8 04 fc ff ff          call   1050 <puts@plt>
-    144c:      b8 01 00 00 00          mov    $0x1,%eax
+    144c:      44 89 f8                mov    %r15d,%eax
+    144f:      90                      nop
+    1450:      90                      nop
     1451:      eb db                   jmp    142e <__cxa_finalize@plt+0x34e>
     1453:      48 8d 3d f5 41 00 00    lea    0x41f5(%rip),%rdi        # 564f <__cxa_finalize@plt+0x456f>
     145a:      e8 f1 fb ff ff          call   1050 <puts@plt>
```

有了这个以后，再去搜索就简单很多了。但是实现的时候，发现在特定位置，有很多种解，这就导致 DFS 的效果比较差，所以这里改成了 BFS，搜索的就比较快了：

```python
from pwn import *
import string
import subprocess


guess = list("flag{") + ["A"] * 19
assert len(guess) == 24
jobs = []
jobs.append((guess, 5))
while len(jobs) > 0:
    job = jobs[0]
    jobs = jobs[1:]
    guess, i = job
    if i == 24:
        continue
    res = []
    for ch in string.ascii_letters + string.digits + string.punctuation:
        guess[i] = ch
        p = subprocess.Popen(
            [
                "./hyperjump_patched",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        p.communicate(input="".join(guess).encode(), timeout=10)[0]
        count = p.returncode
        if count == 0:
            # correct
            count = 24
        res.append((ch, count))
        # print("".join(guess), count)
    print("Best:")
    best = list(sorted(res, key=lambda count: count[1]))[-1]
    for j in range(len(res)):
        if res[j][1] == best[1]:
            guess[i] = res[j][0]
            print("".join(guess), best[1])
            jobs.append((guess.copy(), i + 1))
```

结果：

```
Best:
flag{m4i3d_vm_jump5__42} 24
Best:
flag{m4z3d_vm_jump5__42} 24
Best:
flag{m4!3d_vm_jump5__42} 24
Best:
flag{]4i3d_vm_jump5__42} 24
Best:
flag{]4z3d_vm_jump5__42} 24
Best:
flag{]4!3d_vm_jump5__42} 24
```

经过尝试，`flag{m4z3d_vm_jump5__42}` 是正确的 flag。
