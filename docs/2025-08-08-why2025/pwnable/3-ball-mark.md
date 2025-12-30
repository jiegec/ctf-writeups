# 3 Ball Mark

Decompile via Ghidra:

```c

int __cdecl main(int _Argc,char **_Argv,char **_Env)

{
  bool bVar1;
  int iVar2;
  __time64_t _Var3;
  undefined8 uVar4;
  int local_c;
  
  __main();
  puts(PTR_s_////^\\\\_|_^_^_|_@_(o)_(o)_@_|_<_140004000);
  printf("%s\n\n",msg_start);
  _Var3 = _time64((__time64_t *)0x0);
  srand((uint)_Var3);
  srand(0);
  local_c = 1;
  bVar1 = true;
  while (bVar1) {
    iVar2 = show_try(local_c);
    if (iVar2 == 0) {
      bVar1 = false;
    }
    else {
      if (local_c == 10) {
        uVar4 = create_flag(10);
        printf("\nWell done, here is your reward: %s\n",uVar4);
        bVar1 = false;
      }
      local_c = local_c + 1;
    }
  }
  return 0;
}


undefined8 show_try(uint param_1)

{
  int iVar1;
  undefined8 uVar2;
  int local_c;
  
  printf("\n[+] Try number %d\n",(ulonglong)param_1);
  puts(msg_shuffle);
  shuffle_bag();
  printf("%s",msg_take_a_pick);
  scanf("%d",&local_c);
  if ((local_c < 1) || (3 < local_c)) {
    puts("Invalid choice!");
    uVar2 = 0;
  }
  else {
    iVar1 = strcmp((&bag)[local_c + -1],"Yellow");
    if (iVar1 == 0) {
      puts(msg_correct_pick);
      uVar2 = 1;
    }
    else {
      puts(msg_wrong_pick);
      uVar2 = 0;
    }
  }
  return uVar2;
}
```

It shuffles the array and asks you to find the correct index. But the random seed is constant, so just use trial and error to find the correct sequence: `3333113222`. Use wine to execute the Windows program under Linux.

Solved!
