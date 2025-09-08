# Down the Rabbit Hole

```
By Flagyard
Reversing
Making the file huge means you can't just ChatGPT it.
```

Reading the attachment, found the following code:

```python
def _hard_equality_check(s: str) -> bool:
    bb = _bytes(s)
    if len(bb) != _EXPECT_LEN:
        return False
    exp = _rebuild_expected_bytes()
    if len(exp) != len(bb):
        return False
    mismatch = 0
    for i in range(len(bb)):
        mismatch |= (bb[i] ^ exp[i])
    return mismatch == 0
```

So just print out the expected bytes:

```python
>> print(_rebuild_expected_bytes())
b'BHFlagY{i_th0ught_th1s_wa5_suposs3d_t0_b3_34sy_wh7_is_th3_fl4g_s0_l0ng}'
```
