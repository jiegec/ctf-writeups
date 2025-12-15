# Day 11

Run `/challenge/launch` in GUI mode, a VM is launched. Load `dos/disk1.img`, reboot to install MS-DOS. Then, install MS-DOS according to the instructions, and load `dos/disk2.img` and `dos/disk3.img` when prompted. After finishing the installation, eject the floppy disk and reboot.

Start the network driver: insert `pcnet/disk1.vfd`, goto `A:\PKTDRVR`, run `PCNTPK.COM INT=0x60`. Use `edit` to write the following part to `C:\CFG.TXT`:

```
PACKETINT 0x60
IPADDR 192.168.13.36
NETMASK 255.255.255.0
```

Load `mtcp/disk1.img`. Run `set MTCPCFG=C:\CFG.TXT`, `A:` and `PING.EXE 192.168.13.37`. It should work. To get flag, run `NC.EXE -target 192.168.13.37 1337`. The last challenge is to type the flag one by one.

Reference: <https://www.youtube.com/watch?v=51BfA-nvZD8>

Side note:

Here's my attempt to install lanman:

Then, insert `lanman/disk1.img`, run `SETUP.EXE` in `A:\`, install lanman according to the instructions. Load `lanman/disk2.img` when prompted. Scroll to bottom and select `No Driver`. Give a computer name, do not run lanman with Windows.

After installing, load `pcnet/disk1.vfd`, run `C:\LANMAN.DOS\SETUP.EXE`, Configuration -> Network Drivers -> Add New Config -> Other Driver -> OK -> OK -> MS TCP/IP -> OK -> OK, configure ip address to 192.168.13.36/24, disable DHCP. When prompted to insert DOS DRIVERS 2, insert `lanman/disk3.img`.

After saving configuration, eject floppy and reboot system. When the system starts, we can see the network is up. Now we can successfully run `ping 192.168.13.37` and get response. However, I can't find the tcp client to get flag.
