# Lazy Code 2.0

Decompile via Ghidra:

```c
undefined8 main(void)
{
  uint local_10;
  
  for (local_10 = 1; (int)local_10 < 0x3e9; local_10 = local_10 + 1) {
    printf("[+] Decrypting step %d/1000....\n",(ulong)local_10);
    xor_string(encrypted_flag,
               *(undefined4 *)(xors + (long)(int)((ulong)(long)(int)local_10 % 0x1b) * 4));
    printf("[!] Yawn.... I\'m tired... sleeping for %d seconds\n",(ulong)sleeping_time);
    sleep(sleeping_time);
  }
  printf("Pfff... I\'m done, here is your flag: %s\n",encrypted_flag);
  return 0;
}
```

Simply patch the `sleep(sleeping_time)` call to NOPs, and run the program.

Solved!
