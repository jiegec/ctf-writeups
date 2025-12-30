# ZIGBÄKVÄM

```
All those smart devices in my smart home… but are they really smart?

Hint
```

Open the pcap in wireshark, we can find a request for flag byte:

```
0000   01 88 14 2b 1a 01 f0 2b 1a 00 00 08 00 01 f0 00   ...+...+........
0010   00 1e 24 00 35 00 fc 04 01 01 05 05 ef be 04 10   ..$.5...........
0020   43 54 52 4c 5f 47 45 54 5f 4e 45 58 54 5f 46 4c   CTRL_GET_NEXT_FL
0030   41 47 5f 42 59 54 45                              AG_BYTE
```

Its response is below, with the same sequence number:

```
0000   01 88 fe 2b 1a 00 00 2b 1a 01 f0 08 00 00 00 01   ...+...+........
0010   f0 1e 2a 00 01 00 fc 04 01 35 6f 1c ef be 04 0a   ..*......5o.....
0020   f1 00 18 66                                       ...f
```

Extract all the payloads to get flag:

```python
import json

# tshark -x -2 -R "zbee_nwk" -r challenge.pcap -T json > challenge.json
pkts = json.load(open("challenge.json"))
for pkt in pkts:
    if pkt["_source"]["layers"]["zbee_nwk"]["zbee_nwk.src"] != "0xf001":
        continue
    if pkt["_source"]["layers"]["zbee_zcl"]['zbee_zcl.cmd.tsn'] == "0":
        continue
    for key in pkt["_source"]["layers"]["zbee_zcl"]:
        if key.startswith("Attribute Field"):
            ch = int(key.split()[-1], 16)
            print(chr(ch), end="")
            break
```

Flag: `flag{zigbee_for_smart_home_1s_gr8}`.
