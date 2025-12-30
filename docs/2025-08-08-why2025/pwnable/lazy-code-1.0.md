# Lazy Code 1.0

Decompile via Ghidra:

```c
int __cdecl main(int _Argc,char **_Argv,char **_Env)
{
  uint local_c;
  
  __main();
  for (local_c = 1; (int)local_c < 0x3e9; local_c = local_c + 1) {
    printf("[+] Decrypting step %d/1000....\n",(ulonglong)local_c);
    xor_string(&DAT_140003000,
               *(undefined4 *)
                (&xors + (longlong)
                         (int)(local_c + (int)((ulonglong)(longlong)(int)local_c / 0x1b) * -0x1b) *
                         4));
    printf("[!] Yawn.... I\'m tired... sleeping for %d seconds\n",(ulonglong)sleeping_time);
    sleep(sleeping_time);
  }
  printf("Pfff... I\'m done, here is your flag: %s\n",&DAT_140003000);
  return 0;
}
```

Simply patch the `sleep(sleeping_time)` call to NOPs, and run the program using wine.

Solved!
