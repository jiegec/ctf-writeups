# house-drawin

```
Written by virchau13

This is how it must have felt in the Year of Our Ford.
ssh hexed@challs.watctf.org -p 8022 
```

Attachment:

```python
#!/usr/bin/env python3
import sys
assert sys.stdout.isatty()
flag = open("/flag.txt").read().strip()
to_print = flag + '\r' + ('lmao no flag for you ' * 32)
print(to_print)
```

Redirection output to file:

```shell
$ ssh hexed@challs.watctf.org -p 8022 > out
Connection to challs.watctf.org closed.
$ xxd out
00000000: 7761 7463 7466 7b69 6d5f 6d6f 7265 5f6f  watctf{im_more_o
00000010: 665f 615f 7472 616d 5f66 616e 5f70 6572  f_a_tram_fan_per
00000020: 736f 6e61 6c6c 797d 0d6c 6d61 6f20 6e6f  sonally}.lmao no
00000030: 2066 6c61 6720 666f 7220 796f 7520 6c6d   flag for you lm
```

Flag: `watctf{im_more_of_a_tram_fan_personally}`.
