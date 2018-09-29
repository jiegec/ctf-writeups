Flow 200 points
================

题意
-------------

Try to analyze these flows.

Attachment: flow.zip

解题步骤
-------------

解压缩，得到两个文件： `keyboard.pcap` 和 `network.pcapng` 。

首先打开 `keyboard.pcap` ，可以得到一系列的键盘事件。按照 [CTF Series: Forensics](https://bitvijays.github.io/LFC-Forensics.html) 中的指示可以知道输入的内容为：

```
PACIPH{edcFn0jXzdpdidl}
```

接着分析 `network.pcapng` ，跟踪最后一个 TCP Stream ，得到它的内容：

```
hey man
hi! how are u
pretty good
I am trying to get the flag
well, then these may be helpful
Pav hzvgcvnie dh lvppvzr kn pvup aqr wvvn rpcbkvb hdz crv kn izexpqnqlerkr, qnb hzvgcvnie qnqlerkr kn xqzpkiclqz, bqpkns wqif pd pav Kzqgk oqpavoqpkikqn Ql-Fknbk, jad hdzoqlle bvmvldxvb pav ovpadb (pav ikxavzr wzvqfqwlv we pakr pviankgcv sd wqif qp lvqrp pd pav Iqvrqz ikxavz knmvnpvb we Tclkcr Iqvrqz, rd pakr ovpadb idclb aqmv wvvn vuxldzvb kn ilqrrkiql pkovr).
Pav xqzqszqxa qwdmv kr hzdo Jkfkxvbkq. Javn edc rvv kp edc ocrp aqmv cnbvzrpddb jaqp kr hzvgcvnie dh lvppvzr. Ndj edc aqmv pav fve pd hlqs. Kh edc hknb pavrv iaqllvnsvr knpvzvrpkns, jvlidov pd Zvbwcb qnb rqe avlld pd pav aqifvz jdzlb.
Thx!
Good luck, bye
```

对于恺撒密码，用 QuipQiup 基本可以解出对应关系，然后综合二者，得到 `THUCTF{youKnowProtocol}` 。原文为：

```
The frequency of letters in text has been studied for use in cryptanalysis, and frequency analysis in particular, dating back to the Iraqi mathematician Al-Kindi, who formally developed the method (the ciphers breakable by this technique go back at least to the Caesar cipher invented by Julius Caesar, so this method could have been explored in classical times). 
The paragraph above is from Wikipedia. When you see it you must have understood what is frequency of letters. Now you have the key to flag. If you find these challenges interesting, welcome to Redbud and say hello to the hacker world.
```