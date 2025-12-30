pwn4 400 points
================

题意
-------------

I know you can not exploit my shell

nc host port

Attachment: bash-hacker


解题步骤
-------------

逆向了 `bash-hacker` ，就是任意输入一个名字，然后输入一个足够短（5 字节以内）的一个命令，然后调用 `system()` 。

直接 `bash` 获得 `shell` ，然后 `cat /flag` 得到 `flag`:

```
THUCTF{You_mu5t_Be_4_Hack3r_1n_7he_5hel1}
```
