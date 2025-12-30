# DISCORD SHENANIGANS V5

```
The announcement shenanigans are in play again.
As a small hint, maybe bulking up on the nothingness was the best way to hide it. ;) Go get your shovels ready!

Leave the photos alone, man! The flag is not there.
```

From the discord announcement, there is a message with steganography:

```
@everyone Starting in 3 hours!! (and 15 minutes). Get your shovels ready! 😉 ​‌​‌​‌​​​‌​​​‌‌​​‌​​​​‌‌​‌​​​​‌‌​‌​‌​‌​​​‌​​​‌‌​​‌‌‌‌​‌‌​‌‌​‌​​​​‌‌​‌​​‌​‌‌​​‌​​​‌‌​​‌​​​‌‌​​‌​‌​‌‌​‌‌‌​​‌​‌‌‌‌‌​‌‌‌​​‌‌​‌‌​‌​​​​‌‌​​‌​‌​‌‌​‌‌‌​​‌‌​​​​‌​‌‌​‌‌‌​​‌‌​‌​​‌​‌‌​​‌‌‌​‌‌​​​​‌​‌‌​‌‌‌​​‌‌‌​​‌‌​‌‌‌‌‌​‌

https://ctf.thefewchosen.com/
```

There are hidden \x200B and \x200C characters. Map them to binary 0 and 1 and decode:

```python
import itertools

text = """@everyone Starting in 3 hours!! (and 15 minutes). Get your shovels ready! 😉 ​‌​‌​‌​​​‌​​​‌‌​​‌​​​​‌‌​‌​​​​‌‌​‌​‌​‌​​​‌​​​‌‌​​‌‌‌‌​‌‌​‌‌​‌​​​​‌‌​‌​​‌​‌‌​​‌​​​‌‌​​‌​​​‌‌​​‌​‌​‌‌​‌‌‌​​‌​‌‌‌‌‌​‌‌‌​​‌‌​‌‌​‌​​​​‌‌​​‌​‌​‌‌​‌‌‌​​‌‌​​​​‌​‌‌​‌‌‌​​‌‌​‌​​‌​‌‌​​‌‌‌​‌‌​​​​‌​‌‌​‌‌‌​​‌‌‌​​‌‌​‌‌‌‌‌​‌

https://ctf.thefewchosen.com/"""

data = []

for ch in text:
    if ord(ch) == 0x200B:
        data.append(0)
    elif ord(ch) == 0x200C:
        data.append(1)

# https://stackoverflow.com/questions/20541023/in-python-how-to-convert-array-of-bits-to-array-of-bytes
data = bytes(
    [sum([byte[b] << (7 - b) for b in range(0, 8)]) for byte in zip(*(iter(data),) * 8)]
)

print(data)
```

Get flag: `TFCCTF{hidden_shenanigans}`

It can also be solved online by selecting only U+200B and U+200C: <https://330k.github.io/misc_tools/unicode_steganography.html>
