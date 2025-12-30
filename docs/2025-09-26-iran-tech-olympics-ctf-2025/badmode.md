# Badmode

```
For our software license protection, we've implemented a secret string that complements the license file for authentication. We consider this system to be extremely secure and invincible, and we're seeking your validation. Are we in badmode?
```

Decompile in Ghidra:

```c
iVar3 = strcmp(&stack0xffffffffffffffa0 + lVar2,&secret);
if (iVar3 == 0) {
  sVar4 = strlen(&secret);
  printf("Congratulations! Here is your flag: ASIS{");
  for (local_10 = 0; (local_10 < sVar4 && (local_10 < 0x1c)); local_10 = local_10 + 1) {
    putchar((uint)(byte)((&secret)[local_10] ^ (&DAT_00102a20)[local_10]));
  }
  puts("}");
  DAT_00120190 = 1;
  DAT_0012018c = 1;
}
```

It calls `strcmp` to compare `secret` with some data. Use `ltrace` to find the arguments:

```shell
$ ltrace -o ltrace.log ./badmode license
Please enter the SECRET string to validate license: secret
Your license is NOT valid!
$ cat ltrace.log | grep strcmp
strcmp("8d45ac2d9904d910613f94ba81b5", "secret")                        = -118
$ ./badmode license
Please enter the SECRET string to validate license: 8d45ac2d9904d910613f94ba81b5
Congratulations! Here is your flag: ASIS{ADSB_3nc0din9S_iN__R3vEr5Es!}
```

Flag: `ASIS{ADSB_3nc0din9S_iN__R3vEr5Es!}`.
