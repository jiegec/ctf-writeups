# Bits of Space

```
Bits of Space

Here is a code to one of our relays, can you reach the others?
nc sunshinectf.games 25401 
```

Attachment:

```python
import socket
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from secrets import key

HOST = "0.0.0.0"
PORT = 25401

VALID_DEVICES = {
    0x13371337: b"Status Relay\n",
    0x1337babe: b"Ground Station Alpha\n",
    0xdeadbeef: b"Lunar Relay\n",
    0xdeadbabe: b"Restricted Relay\n"
}

CHANNEL_MESSAGES = {
    1: b"Channel 1: Deep Space Telemetry Stream.\n",
    2: b"Channel 2: Asteroid Mining Operations Log.\n",
    3: b"Channel 3: Secret Alien Communication Feed!\n",
}

def read_flag():
    with open("/flag", "rb") as fl: return fl.readline() + b'\n'

def decrypt_subscription(data: bytes, key: bytes):
    iv = data[:AES.block_size]
    body = data[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(body), AES.block_size)

    device_id, start, end, channel = struct.unpack("<IQQI", plaintext)
    return device_id, start, end, channel

def handle_client(conn):
    try:
        conn.sendall(b"== Space Relay ==\n")
        conn.sendall(b"Send your subscription packet:\n")

        data = conn.recv(1024).strip()
        if not data:
            conn.sendall(b"No data received.\n")
            return

        try:
            device_id, start, end, channel = decrypt_subscription(data, key)
        except Exception as e:
            conn.sendall(b"Invalid subscription. Access denied.\n")
            return

        if device_id not in VALID_DEVICES:
            conn.sendall(b"Unknown device ID. Authentication failed.\n")
            return

        # Secret Device
        if device_id == 0xdeadbabe:
            conn.sendall(b"You have reached the restricted relay... here you go.\n")
            conn.sendall(read_flag())
            return

        if channel not in CHANNEL_MESSAGES:
            conn.sendall(b"Unknown channel. No signal.\n")
            return

        device_name = VALID_DEVICES[device_id]
        conn.sendall(b"Authenticated device: " + device_name)
        conn.sendall(CHANNEL_MESSAGES[channel])

    finally:
        conn.sendall(b"See you next time space cowboy.\n")
        conn.close()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"Satellite relay listening on {HOST}:{PORT}...")

        while True:
            conn, addr = s.accept()
            handle_client(conn)

if __name__ == "__main__":
    main()
```

We are provided a `voyager.bin`, which corresponds to 0x13371337 device id:

```shell
$ cat voyager.bin | nc sunshinectf.games 25401
== Space Relay ==
Send your subscription packet:
Authenticated device: Status Relay

Channel 1: Deep Space Telemetry Stream.
```

Since it is AES-CBC, we can change IV to change the first plain text block given the known plain text part:

```python
from pwn import *

data = open("voyager.bin", "rb").read()
# change device id from:
# 0x13371337: Status Relay
# to
# 0xdeadbabe
iv = bytearray(data[:16])
body = data[16:]
old = struct.pack("<I", 0x13371337)
new = struct.pack("<I", 0xdeadbabe)
for i in range(4):
    iv[i] ^= old[i] ^ new[i]
print(old, new)

p = remote("sunshinectf.games", 25401)
p.send(iv + body)
p.interactive()
```

Flag: `sun{m4yb3_4_ch3ck5um_w0uld_b3_m0r3_53cur3}`.
