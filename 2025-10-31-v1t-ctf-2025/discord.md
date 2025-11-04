# Discord

```
Join our Discord and look at the duck :>
```

In the descriptions of channel `#announcements`, `#updates` and `#ticket`, there are some emojis. Copy them down, concatenate and convert them to bitstream then string:

```python
data = ":v0::v1::v1::v1::v0::v1::v1::v0::v0::v0::v1::v1::v0::v0::v0::v1::v0::v1::v1::v1::v0::v1::v0::v0::v0::v1::v1::v1::v1::v0::v1::v1::v0::v1::v1::v0::v0::v1::v0::v0::v0::v0::v1::v1::v0::v0::v0::v1::v0::v0::v1::v1::v0::v1::v0::v1::v0::v0::v1::v1::v0::v1::v0::v1::v0::v1::v1::v0::v0::v0::v1::v1::v0::v0::v1::v1::v0::v0::v0::v0::v0::v1::v1::v1::v0::v0::v1::v0::v0::v1::v1::v0::v0::v1::v0::v0::v0::v1::v1::v1::v1::v1::v0::v1:"
data = data.replace(":", "").replace("v", "")
n = int(data, 2)
print(data, n, n.to_bytes(20))
```

Flag: `v1t{d155c0rd}`.
