# Pluto Chat

```
We suspect one of our top engineers has been siphoning information from our space operations. We saw some weird chatting app on his computer, so we started capturing packets between him and the chat server. He must've caught on, though, because he shut down the server and these packets are all we have. We think there's some weird encryption going on - can you help us?
```

Decompile in IDA, the program has it encoding/decoding routine that is symmetric, i.e. the sent/receive messages are processed in the same way. So we can replay the encoded input via a fake server.

First, we extract the TCP payload from Wireshark, and save to a file:

```python
# extracted from pcap
data1 = (
    "c6237f77200000007eba8d0f617bf90990dad469793c700fa16724ea028c3d4db57e0c80a077e0d5"
)
data2 = "5961965e01000000f2"
data3 = "43a72f7d4f0000000e6bcbc2f22c2ab292df5214621f539fb64957e5bc263200363280f254c9cef412c3daed1bca89945c4c8de150da6353ec04eb2c44aafb21841041f8dc032f7f31ed4a3d50477a9c5e96ba2c22a88e"
data4 = "7fc8fe7f48000000f31cd383bb6fdd8f41a8924099f79eda967f039fda8253b668843bd32cd8e6b085cd34f14563a3534c61b78e81c2246ed231daa7e93fba5634fe344c0524b1922569b8de54f391ba"

open("plutochat.in", "wb").write(bytes.fromhex(data2)+bytes.fromhex(data3)+bytes.fromhex(data4))
```

Here data1 is the login message with username and password; data2 is the login success message; data3 and data4 are messages sent between users. If we replay the data in a server:

```shell
cat plutochat.in | nc -l -p 31337 -v
```

We can see that one message is shown in plain, but not the other:

```shell
$ ./plutochat
Login to PlutoChat
Username: 1234
Password: 5678
Login successful! Welcome to PlutoChat!
62 14
New message from givemethemoney: Hey can you give me that sensitive key you were talking about?
Type a username to send a message to, or 'EXIT' to exit:
```

The missing message is not printed due to the constraints not satisfied:

```c
if ( v4 == 1 )
 {
   result = puts("Login successful! Welcome to PlutoChat!");
   dword_422C = 1;
 }
 else if ( v10 == 3 )
 {
   v9 = v5;
   v8 = (const char *)malloc(v5 + 1);
   for ( i = 0; i < v9; ++i )
     v8[i] = *((_BYTE *)&buf[2] + i + 2);
   v7 = *((_BYTE *)&buf[2] + v9 + 2);
   v6 = (const char *)malloc(v7 + 1);
   for ( j = 0; j < v7; ++j )
     v6[j] = *((_BYTE *)&buf[2] + v9 + j + 3);
   printf("%d %d\n", v7, v9);
   return printf("New message from %s: %s\n", v8, v6);
 }
```

To recover the data, we set breakpoint at the condition, and when processing the last message, the decode text is shown in stack:

```
00:0000│ rsp 0x7ffff7d92650 ◂— 0
01:0008│-848 0x7ffff7d92658 ◂— 0x300000000
02:0010│-840 0x7ffff7d92660 ◂— 0x487ffec87f
03:0018│ rcx 0x7ffff7d92668 ◂— 0x656d657669670e02
04:0020│-830 0x7ffff7d92670 ◂— "themoney7Of course! It's: sun{S3cur1ty_thr0ugh_Obscur1ty_1s_B4D} about?"
05:0028│-828 0x7ffff7d92678 ◂— "7Of course! It's: sun{S3cur1ty_thr0ugh_Obscur1ty_1s_B4D} about?"
06:0030│-820 0x7ffff7d92680 ◂— "se! It's: sun{S3cur1ty_thr0ugh_Obscur1ty_1s_B4D} about?"
07:0038│-818 0x7ffff7d92688 ◂— ': sun{S3cur1ty_thr0ugh_Obscur1ty_1s_B4D} about?'
```

Flag: `sun{S3cur1ty_thr0ugh_Obscur1ty_1s_B4D}`.
