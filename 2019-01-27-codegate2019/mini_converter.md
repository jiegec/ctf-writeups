mini_conveter
===========================

## Source code

A ruby file is provided like below:

```
flag = "FLAG{******************************}"
# Can you read this? really???? lol

# ...
puts "string to integer"
STDOUT.flush
puts input.unpack("C*#{input}.length")
STDOUT.flush
# ...
```

## Vulernability

The problem lies in "C*#{input}.length", which means we can put everything in the parameter. After some searching, we can find [CVE-2018-8778](https://blog.sqreen.io/buffer-under-read-ruby/), so we can leak memory of any length. 

## Leaking the flag

We found that 2MB is enough to cover the flag so we can use "@18446744073707551416C2000204" for input string and then convert the response to ascii, we can find the flag `flag = "FLAG{Run away ... it}"`

The BUG is fixed in newer versions of Ruby, so we failed to reproduce it at first. The ruby on the remote seems to be 2.5.0.

## See also

[CVE-2018-8778: Buffer under-read in String#unpack](<https://www.ruby-lang.org/en/news/2018/03/28/buffer-under-read-unpack-cve-2018-8778/>)