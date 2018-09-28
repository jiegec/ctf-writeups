Ruby Master - Level 3 150 points
================

题意
-------------

Final level, beat it!

Steal flag from level3.rb and level3_flag.rb

The attachment is the same is level 1 & 2

Server: nc host port

Attachment: ruby_master.zip

解题步骤
-------------

任务：

level3.rb：

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

level3_flag.rb：

```
# FLAG is THUCTF{CENSORED}
```

虽然文字在注释中，但仍然在内存里。

```
ObjectSpace.each_object(String) {|x| p x if /THUCTF\{/ =~ x}
```

得到：

```
# FLAG is THUCTF{Th3_rea1_RUBY_Mast3r_1s_y0u!}
```