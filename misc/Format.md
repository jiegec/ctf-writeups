Format 200 points
================

题意
-------------

A set of several small misc challenges for beginners. Have fun!

Check this little stuff:

UEsDBBQACQBjABaIKE1vm4SuOgAAABwAAAAEAAsAZmxhZwGZBwABAEFFAwgApWUQlimQ7meiBo6QS8LoGxVv7Dj2gtSxLCjs/tIZsbyVPmUp/B7SzNBzCwv86/g02+H994xFQ5Ry3lBLBwhvm4SuOgAAABwAAABQSwECHwAUAAkAYwAWiChNb5uErjoAAAAcAAAABAAvAAAAAAAAACAAAAAAAAAAZmxhZwoAIAAAAAAAAQAYANxyD6pBR9QBb62NUUFH1AFvrY1RQUfUAQGZBwABAEFFAwgAUEsFBgAAAAABAAEAYQAAAHcAAAAAAA==

Attachment: format.zip

解题步骤
-------------

在 format.zip 里面有一张图片，通过 `StegSolve.jar` 发现左上角有一个隐写的二维码，扫描出来得到：

```
XRL:QNGN+SBEZNG=VASBEZNGVBA
```

ROT-13 解码后：

```
KEY:DATA+FORMAT=INFORMATION
```

用 `DATA+FORMAT=INFORMATION` 解压缩，得到 `THUCTF{juSt_@_pieCe_0f_c@ke}` 。