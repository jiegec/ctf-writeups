# Intergalactic Copyright Infringement

```
NASA received a notification from their ISP that it appeared that some copyrighted files were transferred to and from the ISS (Guess astronauts need movies too). We weren't able to recover the all of the files, but we were able to capture some traffic from the final download before the user signed off. If you can help recover the file that was downloaded perhaps you can shed some light on what they were doing?
```

The provided attachment contains multiple BitTorrent packets. Each packet corresponds to a piece of data. We reassmebled the data to construct the original PDF file:

```python
# tshark -x -2 -R "bittorrent" -r evidence.pcapng -T json > copyright.json
import os
import json

all_data = json.load(open("copyright.json"))
for entry in all_data:
    layers = entry["_source"]["layers"]
    if "bittorrent" in layers:
        bt = layers["bittorrent"]
        if "bittorrent.msg" in bt:
            msg = bt["bittorrent.msg"]
            if "bittorrent.piece.data_raw" in msg:
                index = msg["bittorrent.piece.index"]
                begin = msg["bittorrent.piece.begin"]
                data_raw = msg["bittorrent.piece.data_raw"]
                data = bytes.fromhex(data_raw[0])
                print(index, begin, len(data))

                path = "copyright-" + str(int(index, 16))
                if not os.path.isfile(path):
                    open(path, "w").close()
                f = open(path, "r+b")
                f.seek(int(begin, 16), os.SEEK_SET)
                f.write(data)
                f.close()

# concat pieces
data = bytearray()
for i in range(21):
    data += open("copyright-" + str(i), "rb").read()

open("copyright.pdf", "wb").write(data)
```

Flag in PDF:

![](./intergalactic-copyright-infringement.png)
