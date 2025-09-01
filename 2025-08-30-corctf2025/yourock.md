# yourock

```
Forget Enigma, forget Caesar. The only cipher you need is 2009's infamous password dump.
```

Attachment contains a encoded text:

```
charlie junior babygirl soccer qwerty 111111 000000 tigger jessica jasmine joseph 12345 tigger chelsea melissa 123123 mickey computer anthony chelsea brandon brandon matthew soccer bubbles playboy spongebob eminem ashley password ashley
```

Decompiled `encode` program via IDA by @rosayxy:

```c++
// a1: result string, printed to encoded.rj
// a2: input string, contains flag
// a3: vector of strings, read from rockyou.txt
// a4: a random number
__int64 __fastcall encode(__int64 a1, __int64 a2, __int64 a3, unsigned __int8 a4)
{
  __int64 v4; // rax
  __int64 v5; // rax
  unsigned __int8 v9; // [rsp+27h] [rbp-19h]
  unsigned __int64 i; // [rsp+28h] [rbp-18h]

  std::vector<std::string>::vector(a1);
  v4 = std::vector<std::string>::operator[](a3, a4);
  std::vector<std::string>::push_back(a1, v4);
  for ( i = 0LL; i < std::string::size(a2); ++i )
  {
    v9 = a4 ^ *(_BYTE *)std::string::operator[](a2, i);
    if ( v9 >= (unsigned __int64)std::vector<std::string>::size(a3) )
      exit(1);
    v5 = std::vector<std::string>::operator[](a3, v9);
    std::vector<std::string>::push_back(a1, v5);
    a4 ^= i ^ v9;
  }
  return a1;
}
```

We can grab a copy of `rockyou.txt` from web, then find `v9` in each iteration to compute each byte in the input string, which contains the flag:

```python
# from encoded.rj
encoded = "charlie junior babygirl soccer qwerty 111111 000000 tigger jessica jasmine joseph 12345 tigger chelsea melissa 123123 mickey computer anthony chelsea brandon brandon matthew soccer bubbles playboy spongebob eminem ashley password ashley"
# rockyou.txt from web
words = open("rockyou.txt", "r", encoding='latin-1').readlines()
key = words.index("charlie\n")
i = 0
res = ""
for part in encoded.split()[1:]:
    index = words.index(part + "\n")
    ch = index ^ key
    res += chr(ch)
    key = key ^ index ^ i
    i += 1
print(res)
```

Get flag: `corctf{r0cky0u_3nc0d1ng_r0cks}`.
