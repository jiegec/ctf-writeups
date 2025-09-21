# discord

```
Make sure to join our awesome discord server (https://discord.gg/QeCGUhbjXx) and look in #announcements!

Anyways, here's a random quote:

    "Beware the man who speaks in squares"

Note: You do not need to open a ticket or send any messages to solve this challenge.
```

There are hidden 0x9e and 0x9f characters in the following message:

```
Hey, sorry about the delay but it looks we reached the global IP quota limit 💀

if you see a challenge is down, move onto a different challenge or try solving it locally. once again, really sorry everybody
 <9e><9f><9e><9e><9f><9e><9f><9f><9e><9e><9f><9f><9e><9e><9e><9f><9e><9e><9f><9f><9e><9f><9f><9f><9e><9f><9f><9f><9f><9e><9f><9f><9e><9f><9f><9f><9e><9f><9f><9f><9e><9f><9f><9e><9e><9f><9e><9f><9e><9f><9e><9e><9f><9f><9e><9e><9e><9f><9f><9e><9e><9e><9f><9f><9e><9e><9f><9f><9e><9e><9e><9e><9e><9f><9f><9e><9f><9f><9e><9f><9e><9e><9f><9f><9e><9e><9f><9f><9e><9f><9e><9f><9f><9f><9f><9f><9e><9f><9f><9f><9e><9f><9e><9e><9e><9e><9f><9f><9e><9e><9e><9e><9e><9f><9e><9f><9f><9f><9f><9f><9e><9f><9f><9e><9f><9e><9f><9f><9e><9e><9f><9f><9e><9e><9e><9f><9e><9e><9f><9f><9e><9f><9f><9f><9e><9f><9e><9f><9f><9f><9f><9f><9e><9f><9e><9e><9e><9e><9f><9f><9e><9e><9f><9f><9e><9f><9f><9f><9e><9f><9e><9e><9e><9f><9f><9e><9e><9e><9f><9e><9e><9e><9e><9f><9e><9e><9f><9e><9e><9e><9e><9f><9e><9e><9f><9e><9e><9e><9e><9f><9e><9f><9f><9f><9f><9f><9e><9f>
cameron
```

Decode by mapping 0x9e to bit 0, 0x9f to bit 1:

```python
text = open("discord.txt", "r").read()

data = []

for ch in text:
    if ord(ch) == 0x9e:
        data.append(0)
    elif ord(ch) == 0x9f:
        data.append(1)

# https://stackoverflow.com/questions/20541023/in-python-how-to-convert-array-of-bits-to-array-of-bytes
data = bytes(
    [sum([byte[b] << (7 - b) for b in range(0, 8)]) for byte in zip(*(iter(data),) * 8)]
)

print(data)
```

Flag: `K17{weLc0m3_t0_k17_C7F!!!}`.
