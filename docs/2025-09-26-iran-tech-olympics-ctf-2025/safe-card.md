# Safe card

```
Oops! It looks like someone left their smart safe card behind, but the reader isn’t working properly. To unlock the door, you’ll need to connect to the card reader emulator, locate the flag inside its memory, and enter it to gain access!

nc 65.109.184.29 1337
```

We are given a console to transceive APDUs. According to the attachment, we first select the aid via:

```
00 A4 04 00 0A F0 21 85 4C D8 D9 80 0A FF 67
```

1. `00 A4 04 00`: select aid
2. `0A`: aid length, 10
3. `F0 21 85 4C D8 D9 80 0A FF 67`: aid from the attachment

Then, we can read binary contents with:

```
00 B0 xx yy FF
```

1. `00 B0`: read binary
2. `xx yy`: read offset
3. `FF`: response size

Then we can read from different offsets to enumerate the contents:

```python
from pwn import *

context(log_level = "DEBUG")

p = remote("65.109.184.29", 1337)
# SELECT AID
p.sendline(b"00 A4 04 00 0A F0 21 85 4C D8 D9 80 0A FF 67")
p.recvuntil(b"9000")
# READ BINARY
for i in range(256):
    addr = f"{i * 128:04X}"
    addr = addr[:2] + " " + addr[2:]
    p.sendline(f"00 B0 {addr} FF".encode())
    data = p.recvuntil(b"9000")
    data = bytes.fromhex(data.decode())
    print(data)
```

Flag: `ASIS{W4tch_y0ur_c4rd5!}`.
