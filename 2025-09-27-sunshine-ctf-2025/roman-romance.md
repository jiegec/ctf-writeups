# Roman Romance

```
currently has nonstandard flag format sunshine{}
```

Decompile in IDA:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 i; // [rsp+68h] [rbp-28h]
  FILE *stream; // [rsp+70h] [rbp-20h]
  __int64 size; // [rsp+78h] [rbp-18h]
  _BYTE *ptr; // [rsp+80h] [rbp-10h]
  FILE *s; // [rsp+88h] [rbp-8h]

  stream = fopen("flag.txt", "r+b");
  fseek(stream, 0, 2);
  size = ftell(stream);
  rewind(stream);
  ptr = malloc(size);
  if ( ptr )
  {
    if ( fread(ptr, 1u, size, stream) == size )
    {
      for ( i = 0; i < size; ++i )
        ++ptr[i];
      fclose(stream);
      s = fopen("enc.txt", "w");
      if ( fwrite(ptr, 1u, size, s) == size )
      {
        free(ptr);
        fclose(s);
        puts(a38213900m);
        puts("/*************************************************************************************\\ \n");
        puts("  MWAHAAHAHAH SAY GOOD-BYTE TO YOUR FLAG ROMAN FILTH!!!!! >:) ");
        puts("  OUR ENCRYPTION METHOD IS TOO STRONG TO BREAK. YOU HAVE TO PAY US >:D ");
        puts("  PAY 18.BTC TO THE ADDRESS 1BEER4MINERSMAKEITRAINCOINSHUNT123 TO GET YOUR FLAG BACK,  ");
        puts("  OR WE SACK ROME AND I TAKE HONORIA'S HAND IN MARRIAGE! SIGNED, ATTILA THE HUN.  \n");
        puts("/*************************************************************************************\\ \n");
        return 0;
      }
      else
      {
        perror("fwrite");
        free(ptr);
        fclose(s);
        return 1;
      }
    }
    else
    {
      perror("fread");
      free(ptr);
      fclose(stream);
      return 1;
    }
  }
  else
  {
    fwrite("malloc failed\n", 1u, 0xEu, stderr);
    fclose(stream);
    return 1;
  }
}
```

It increments each byte from input. Solve:

```python
for ch in open("enc.txt", "r", encoding="utf-8").read():
    print(chr(ord(ch)-1), end="")
```

Flag: `sunshine{kN0w_y0u4_r0m@n_hI5t0rY}`.
