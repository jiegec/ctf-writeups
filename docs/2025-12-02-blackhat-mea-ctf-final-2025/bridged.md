# Bridged

Extract the E01 file in attachment:

```shell
7z x Bridged.zip
mkdir mnt
ewfmount Bridged.E01 mnt
cp mnt/ewf1 .
sudo losetup -f ewf1
sudo mount /dev/loop0 mnt
```

Find files modified lately:

```shell
$ sudo find . -mtime -40
./var/snap/docker/common/var-lib-docker/overlay2/97840775eed658e913b9fe59d53fe5686411023c7fcb965491a667a3b131fd55/diff/usr/local/bin
./var/snap/docker/common/var-lib-docker/overlay2/97840775eed658e913b9fe59d53fe5686411023c7fcb965491a667a3b131fd55/diff/usr/local/bin/monitor_system
./var/snap/docker/common/var-lib-docker/overlay2/214314ccf4e859b4acdc9ed5d7b9077b6885a7b6b1033a7662a8f5298e55fdf0/diff/usr/local/bin
./var/snap/docker/common/var-lib-docker/overlay2/214314ccf4e859b4acdc9ed5d7b9077b6885a7b6b1033a7662a8f5298e55fdf0/diff/usr/local/bin/monitor_system
```

Decompile the `monitor_system` file, it decodes itself and call `execve`, so we extract the decoded elf from `/proc`:

```shell
./monitor_system &
cp /proc/1484585/exe decoded_elf
```

Find some base64 within:

```shell
 g1ft: QkhGbGFnWXthNDUyM2MxZjd
TgGVkOWFmYTRiZGE1MTQ1NmI5
Zn0=
```

Run the decoded_elf and get coredump:

```shell
$ ulimit -c 8192
$ ./decoded_elf
# press Ctrl-\ to create coredump
$ strings coredump-NbgWcy | grep g1ft
Here is your g1ft: QkhGbGFnWXthNDUyM2MxZjdhNTgyMGVkOWFmYTRiZGE1MTQ1NmI5Zn0=   o) Chrome/117.0.0.0 Safari/537.36
```

Decode base64:

```shell
$ echo "QkhGbGFnWXthNDUyM2MxZjdhNTgyMGVkOWFmYTRiZGE1MTQ1NmI5Zn0=" | base64 -d
BHFlagY{a4523c1f7a5820ed9afa4bda51456b9f}
```
