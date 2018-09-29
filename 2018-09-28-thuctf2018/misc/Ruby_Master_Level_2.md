Ruby Master - Level 2 150 points
================

题意
-------------

Now try harder to next level, try to extract flag hidden in level2.rb

The attachment is the same as level 1

Server: nc host port

Attachment: ruby_master.zip

解题步骤
-------------

任务：

```
require_relative 'restrict'
Restrict.set_timeout

def get_flag(x)
  flag = "THUCTF{CENSORED}"
  x
end

input = STDIN.gets
fail unless input
input.size > 60 && input = input[0, 60]

Restrict.seccomp

STDOUT.puts get_flag(eval(input))
```

通过字节码获得函数中的字符串常量

```
RubyVM::InstructionSequence.disasm(method(:get_flag))
```

得到：

```
THUCTF{N1ce_try_n0W_f1nal_stag3}
```