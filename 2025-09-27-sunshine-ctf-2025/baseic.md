# BASEic

```
The space base is in danger and we lost the key to get in!
```

Decomple in IDA:

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  size_t v3; // rax
  size_t v4; // rax
  char *s1; // [rsp+8h] [rbp-58h]
  char s2[14]; // [rsp+12h] [rbp-4Eh] BYREF
  char s[56]; // [rsp+20h] [rbp-40h] BYREF
  unsigned __int64 v9; // [rsp+58h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  strcpy(s2, "yX0I0NTM1fQ==");
  printf("What is the flag> ");
  __isoc99_scanf("%40s", s);
  if ( strlen(s) == 22 )
  {
    v3 = strlen(s);
    s1 = (char *)sub_12C6(s, v3);
    if ( !strncmp(s1, "c3Vue2MwdjNyMW5nX3V", 0x13u) )
    {
      v4 = strlen(s2);
      if ( !strncmp(s1 + 19, s2, v4) )
        puts("You got it, submit the flag!");
      else
        puts("Soo Close");
    }
    else
    {
      puts("Closer");
    }
    free(s1);
  }
  else
  {
    puts("You don't get the flag that easily");
  }
  return 0;
}
```

The code compares the base64 encoded input with `c3Vue2MwdjNyMW5nX3VyX0I0NTM1fQ==`, solve:

```shell
echo "c3Vue2MwdjNyMW5nX3VyX0I0NTM1fQ==" | base64 -d
```

Flag: `sun{c0v3r1ng_ur_B4535}`.
