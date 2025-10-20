# Hack.lu CTF 2025 FÄNGELSE

```python
flagbuf = open("flag.txt", "r").read()

while True:
    try:
        print(f"Side-channel: {len(flagbuf) ^ 0x1337}")
    # Just in case..
    except Exception as e:
        # print(f"Error: {e}") # don't want to leak anything
        exit(1337)
    code = input("Code: ")
    if len(code) > 5:
        print("nah")
        continue
    exec(code)
```

Requirements:

1. No more than 5 characters: use `exit(flagbuf)` to leak flag, use `a=exit;len=a` to override function in two steps, use `ⅺ` for `xi` to break the length limitation

Solution by @moritz on Discord:

```shell
$ xn--fngelse-5wa.solven.jetzt 1024
Side-channel: 4890
Code: a=eⅺt
Side-channel: 4890
Code: len=a
flag{1_2_3_4_5_6_7_8_9_10_exploit!_12_13_...}
```

The length of `a=exit` is 6, but using `ⅺ` reduces it to 5. Then, `exit(flagbuf)` is called to print the flag.
