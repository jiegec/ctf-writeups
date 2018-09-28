Pixels 100 points
================

题意
-------------

Our captain hides behind mosaic

Attachment: thupixels.zip

解题步骤
-------------

打开图片，啥都看不出，肯定是隐藏了信息。把 `IDAT` 中内容拿出来用 `zlib` 解压看了下，大概是这样的：

```
00000000: 0189 504e bebd bcd3 fdf6 e6f6 0d49 4837  ..PN.........IH7
00000010: 09b8 bcb5 8000 f984 3808 fec8 f8fe 67b1  ........8.....g.
00000020: 56ad 4faa f6bc 6939 87e7 0126 232c 03ee  V.O...i9...&#,..
00000030: 0994 9fcf 8995 4eee bfbd 02c2 7476 6568  ......N.....tveh
```

仔细观察，里面有 `PN` 和 `IH` 字样，使用 `StegSolve.jar` 提取红绿蓝三个通道，果然是一个合法的 `PNG` 文件。打开以后，图中有两个人，左边人说 `Tell me flag?` ，右边人说 `THUCTF{QuencH_l0ve_B1EaCH}` 。

