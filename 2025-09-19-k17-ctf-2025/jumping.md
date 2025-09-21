# jumping

```
I made this game in high school and I can't seem to clear it! Can you help? Surely you wouldn't cheat!
```

Extract the attachment using <https://github.com/extremecoders-re/pyinstxtractor>:

```shell
python3 pyinstxtractor.py jumping
```

Decompile the extracted `test.pyc` in <https://pylingual.io>:

```python
somemoretext = bytes((x ^ y for x, y in zip([69, 83, 248, 247, 201, 230, 244, 121, 219, 149, 77, 175, 159, 11, 129, 102, 49, 30, 62, 228, 158, 79, 255, 208, 124, 102, 127, 119, 154, 15, 145, 121, 140, 229, 51, 221, 77, 72, 73, 28, 30, 78, 225, 229, 172, 57, 45, 65, 252, 48], b'\x0eb\xcf\x8c\xf8\xb9\xc0:\xec\xe0y\xe3\xd3r\xde"\x01P\t\xbb\xd5!\xcf\xa7#W9(\xadg\xa5N\xd3\xafF\x90=\x17x)A>\xd1\xd0\x99\x08o-\xb9M'))).decode()
display_message('You win!')
display_message(somemoretext, 2)
```

Print `somemoretext` to get flag.

Flag: `K17{1_4C7u4LLy_D0N7_Kn0w_1F_7h47_JuMp_15_p0551BlE}`.
