# Rusted Oracle

Decompile in IDA:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-54h]
  char s[76]; // [rsp+10h] [rbp-50h] BYREF
  int v6; // [rsp+5Ch] [rbp-4h]

  v6 = 0;
  memset(s, 0, 0x40u);
  printf("A forgotten machine still ticks beneath the stones.\n");
  printf("Its gears grind against centuries of rust.\n");
  printf("\n[ a stranger approaches, and the machine asks for their name ]\n");
  printf("> ");
  fflush(stdout);
  v4 = read(0, s, 0x3Fu);
  if ( v4 >= 0 )
  {
    if ( s[v4 - 1] == 10 )
      s[v4 - 1] = 0;
    if ( !strcmp(s, "Corwin Vell") )
    {
      printf("[ the gears begin to turn... slowly... ]\n");
      fflush(stdout);
      machine_decoding_sequence();
    }
    else
    {
      printf("[ the machine falls silent ]\n");
    }
    return 0;
  }
  else
  {
    perror("read");
    return 1;
  }
}

int machine_decoding_sequence()
{
  unsigned int v0; // eax
  int i; // [rsp+Ch] [rbp-24h]
  char s[32]; // [rsp+10h] [rbp-20h] BYREF

  memset(s, 0, 0x18u);
  v0 = rand();
  sleep(v0);
  for ( i = 0; (unsigned __int64)i < 0x17; ++i )
  {
    enc[i] ^= 0x524EuLL;
    enc[i] = __ROR8__(enc[i], 1);
    enc[i] ^= 0x5648uLL;
    enc[i] = __ROL8__(enc[i], 7);
    enc[i] >>= 8;
    s[i] = enc[i];
  }
  return printf("On a rusted plate, faint letters reveal themselves: %s\n", s);
}
```

Patch the call to `sleep` to nop sequences. Then, input `Corwin Vell` to get flag:

```shell
$ ./rusted_oracle
A forgotten machine still ticks beneath the stones.
Its gears grind against centuries of rust.

[ a stranger approaches, and the machine asks for their name ]
> Corwin Vell
[ the gears begin to turn... slowly... ]
On a rusted plate, faint letters reveal themselves: HTB{sk1pP1nG-C4ll$!!1!}
```

Flag: `HTB{sk1pP1nG-C4ll$!!1!}`.
