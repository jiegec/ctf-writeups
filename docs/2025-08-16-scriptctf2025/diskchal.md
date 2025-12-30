# diskchal

Downloaded is a disk image with a flag in it. Use binwalk to solve it:

```shell
$ binwalk -e stick.img
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
404992        0x62E00         gzip compressed data, has original file name: "flag.txt", from Unix, last modified: 2025-07-17 22:27:22
$ cat _stick.img.extracted/flag.txt
scriptCTF{1_l0v3_m461c_7r1ck5}
```
