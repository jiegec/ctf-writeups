godaddy 300 points
================

题意
-------------

Try to give daddy correct flag!

Attachment: godaddy.zip

解题步骤
-------------

经过逆向，大概是这么一个过程：

1. 父进程 fork 出一个子进程
2. 通过 ptrace 检查子进程一段代码是否没有变更
3. 通过 ptrace 修改子进程的一段代码

需要进行脱壳，我采用的方法是，解析 `strace` 输出的 `ptrace()` 函数调用，然后更新（[godaddy.py](godaddy.py)）：

```
from pwn import *
e = ELF('./godaddy')
with open('godaddy.txt', 'r') as fd:
    lines = fd.readlines()
    for line in lines:
        line = line.strip()
        if not len(line):
            continue
        address = int(line[:line.find(',')],16)
        code = int(line[line.find(',')+1:],16)
        print '%x %x' % (address, code)
        e.p64(address, code)

e.save('./godaddy_new')
```

接着进行逆向，这里的汇编代码比较简短已读，用 Python 逆向即可（[godaddy_solve.py](godaddy_solve.py)）：

```
s1=[0x8D,0x5D,0x88,0xA0,0x89,0x5F,0xA2,0x5F,0xFA,0x59,0xF7,0x46,0x94,0x66,0x90,0x69,0xBD,0x66,0x92,0x1E,0xFD,0x1C,0xAE,0x1F,0xF9,0x72,0x82,0x5F,0xE6,0x0C]
res = ''
for i in range(0, len(s1)):
    if i % 2 == 1:
        res+=(chr((s1[i]^0xDD)-0x37-i))
    else:
        res+=(chr((s1[i]^0xCC)+0x13-i))
print(repr(res))
```

得到结果 `THUCTF{DADDY_wants_y0u_t0_G0!}` 。

