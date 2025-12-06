# Rosetta 3 Writeup

## 题目描述

题目提供了一段加密字符串，要求解密其含义。字符串分为三段，每段使用不同的编码方式。

```
You got the following cryptic string from a Rosetta Stone from the 21st century. What does it mean?

0 00 00 00 0 00 00 0 0 00 00 0 0 00 00 00 0 00 00 0000 0 000 00 00 0 0000000 00 0 0 00000 00 0 0 0 00 00 0 00 00 0 0 0 00 000 0 00 00 00 0 0 00 0 0 0000 00 00 0 0 00 0 0 00 00 00 0 0 00 0 0 00 00 0 0 0000000 00 0000 0 0000 00 00 0 0 00 0 0 00 00 00 0 0 00 0 0 00 00 0 0 0000000 00 0 0 00 00 0 0 000 00 0000 0 000 00 0 0 000 00 0 0 0000 00 00 0 00 00 0 0 00000000 00 0 0 00000 00 00 0 0 00 0 0 0
89 99 84 6D 99 85 97 99 85 A2 85 95 A3 81 A3 89 96 95 6D 96 86 6D A3 85 A7 A3 A2 6D 83 81 95 6D A8 96
/=5]D96-R>7!T7W1H96U]
```

## 解题思路

本题考察三种不同的编码方式，需要分别识别并解码每段字符串。

### 第一段：Chuck Norris Unary Code

第一段字符串由 0 和空格组成，这是 Chuck Norris Unary Code 的特征：

```
0 00 00 00 0 00 00 0 0 00 00 0 0 00 00 00 0 00 00 0000 0 000 00 00 0 0000000 00
0 0 00000 00 0 0 0 00 00 0 00 00 0 0 0 00 000 0 00 00 00 0 0 00 0 0 0000 00 00 0
0 00 0 0 00 00 00 0 0 00 0 0 00 00 0 0 0000000 00 0000 0 0000 00 00 0 0 00 0 0
00 00 00 0 0 00 0 0 00 00 0 0 0000000 00 0 0 00 00 0 0 000 00 0000 0 000 00 0 0
000 00 0 0 0000 00 00 0 00 00 0 0 00000000 00 0 0 00000 00 00 0 0 00 0 0 0
```

**解码方法**：使用 [Chuck Norris Unary Code 解码器](https://www.dcode.fr/chuck-norris-code)

**解码结果**：

```
flag{there_are_many_we
```

### 第二段：EBCDIC 编码

第二段字符串是十六进制值，这是 EBCDIC 编码的特征：

```
89 99 84 6D 99 85 97 99 85 A2 85 95 A3 81 A3 89 96 95 6D 96 86 6D A3 85 A7 A3 A2
6D 83 81 95 6D A8 96
```

**解码方法**：使用 [EBCDIC 编码解码器](https://www.dcode.fr/ebcdic-encoding)

**解码结果**：
```
ird_representation_of_texts_can_yo
```

### 第三段：UUencode 编码

第三段字符串包含特殊字符，这是 UUencode 编码的特征：

```
/=5]D96-R>7!T7W1H96U]
```

**解码方法**：使用 [UUencode 解码器](https://www.dcode.fr/uu-encoding)

**解码结果**：

```
u_decrypt_them}
```

## 最终结果

将三段解码结果拼接起来：

```
flag{there_are_many_weird_representation_of_texts_can_you_decrypt_them}
```

## 类似题目

国外 CTF 比赛中经常出现各种字符串编解码的 Misc 题目，例如：

- [scriptCTF 2025 enchant](../../2025-08-16-scriptctf2025/enchant.md)
- [BrunnerCTF 2025 The Great Mainframe Bake-Off](../../2025-08-22-brunnerctf2025/the-great-mainframe-bake-off.md)
- [BrunnerCTF 2025 Pie Recipe](../../2025-08-22-brunnerctf2025/pie-recipe.md)
- [TFC CTF 2025 DISCORD SHENANIGANS V5](../../2025-08-29-tfcctf2025/discord-shenanigans-v5.md)
