# the poop challenge

```
its da poop challenge :DDDDDDDDDD
```

There are hidden 0x200B characters between emojis. They are mapped to binary 1, otherwise 0 if absent:

```python
text = open("poop_challenge.txt", encoding="utf-8").readlines()

data = []

for line in text:
    for i in range(len(line)):
        if ord(line[i]) == ord("💩"):
            if i < len(line) and ord(line[i+1]) == 0x200B:
                data.append(1)
            else:
                data.append(0)

# https://stackoverflow.com/questions/20541023/in-python-how-to-convert-array-of-bits-to-array-of-bytes
data = bytes(
    [sum([byte[b] << (7 - b) for b in range(0, 8)]) for byte in zip(*(iter(data),) * 8)]
)

print(data)
```

Flag: `sun{lesssgooo_solved_the_poop_challenge!}`.