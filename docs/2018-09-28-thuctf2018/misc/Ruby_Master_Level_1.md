Ruby Master - Level 1 50 points
================

题意
-------------

Try to get the hidden flag in the ruby script and become ruby master!

First, let's try something simple in level1.rb

Server: nc host port

Attachment: ruby_master.zip

解题步骤
-------------

任务：

```
require_relative 'restrict'
Restrict.set_timeout

class Private
  private
  public_methods.each do |method|
    eval "def #{method.to_s};end"
  end

  def flag
    return "THUCTF{CENSORED}"
  end
end

p = Private.new
Private = nil

input = STDIN.gets
fail unless input
input.size > 24 && input = input[0, 24]

Restrict.seccomp

STDOUT.puts eval(input)
```

突破访问权限制：

```
def p.a() flag end;p.a
```

得到：

```
THUCTF{G00d_now_h3ad_f0r_the_n3xt}
```