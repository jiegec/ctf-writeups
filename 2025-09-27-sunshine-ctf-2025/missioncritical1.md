# Missoncritical1

```
Ground Control to Space Cadet!

We've intercepted a satellite control program but can't crack the authentication sequence. The satellite is in an optimal transmission window and ready to accept commands. Your mission: Reverse engineer the binary and find the secret command to gain access to the satellite systems.
```

Decompile in IDA:

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char v4[64]; // [rsp+0h] [rbp-98h] BYREF
  char s[56]; // [rsp+40h] [rbp-58h] BYREF
  unsigned __int64 v6; // [rsp+78h] [rbp-20h]

  v6 = __readfsqword(0x28u);
  sprintf(v4, "sun{%s_%s_%s}\n", "e4sy", "s4t3ll1t3", "3131");
  time(0);
  printf("Satellite Status: Battery=%d%%, Orbit=%d, Temp=%dC\n", 80, 32, -25);
  printf("Enter satellite command: ");
  fgets(s, 50, stdin);
  if ( !strcmp(s, v4) )
    puts("Access Granted!");
  else
    puts("Access Denied!");
  return 0;
}
```

The flag is the result of `sprintf`.

Flag: `sun{e4sy_s4t3ll1t3_3131}`.