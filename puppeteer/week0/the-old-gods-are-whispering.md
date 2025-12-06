# The Old Gods Are Whispering Writeup

## 题目描述

本题是一个音频隐写挑战。[附件](./the-old-gods-are-whispering.wav)是一个 WAV 音频文件，其中隐藏了 Flag。

## 隐写技术分析

本题使用了 [Bebra777228/Audio-Steganography](https://github.com/Bebra777228/Audio-Steganography) 工具将文本信息隐藏在音频的频域中。这种隐写技术通过修改音频信号的频率成分来嵌入信息。

## 解题方法

1. 下载并安装 [Sonic Visualizer](https://www.sonicvisualiser.org/)
2. 打开音频文件 `the-old-gods-are-whispering.wav`
3. 添加频谱图（Spectrogram）图层
4. 调整频谱图参数以获得清晰的文本显示

## 结果

通过频谱图分析，可以清晰地看到隐藏的文本：

![](./the-old-gods-are-whispering.png)

隐藏的文本为：`flag{audio_steganography_for_fun}`

## 总结

本题展示了音频隐写的基本原理。音频隐写是一种常见的信息隐藏技术，通过修改音频信号的某些特性（如频域、时域或相位）来嵌入信息。在 CTF 比赛中，音频隐写题目通常需要选手使用专业的音频分析工具来发现和提取隐藏的信息。
