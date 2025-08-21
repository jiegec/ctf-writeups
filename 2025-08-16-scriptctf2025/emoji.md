# emoji

```
Emojis everywhere! Is it a joke? Or something is hiding behind it.
```

File content:

```
🁳🁣🁲🁩🁰🁴🁃🁔🁆🁻🀳🁭🀰🁪🀱🁟🀳🁮🁣🀰🁤🀱🁮🁧🁟🀱🁳🁟🁷🀳🀱🁲🁤🁟🀴🁮🁤🁟🁦🁵🁮🀡🀱🁥🀴🀶🁤🁽
```

Observe the unicode codepoints, found that `str[1] - str[0] == 'c' - 's'`, suggesting that it is the flag offseted by a constant offset:

```python
data = open("out.txt", "r", encoding="utf-8").read()
diff = ord(data[0]) - ord("s")
for ch in data:
    print(chr(ord(ch) - diff), end="")
```

Get flag: `scriptCTF{3m0j1_3nc0d1ng_1s_w31rd_4nd_fun!1e46d}`
