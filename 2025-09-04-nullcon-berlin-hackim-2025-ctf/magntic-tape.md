# Magnetic tape

```
We asked an LLM to build a web app to manage the magnetic tapes archives in our datacenter. We've asked it to make sure it's secure. Could you please do a bit of paid pentestingsecurity research on it? kthxbye

http://52.59.124.14:5005
```

In attachment, the source code of a web server is provide. The flag endpoint is protected by cookie session:

```python
@app.route("/get-flag")
@login_required
def get_session():
    if not session["is_admin"]:
        abort(401)
    flag_path = os.getenv("FLAG_PATH", "flag/flag.txt")
    with open(flag_path) as f:
        return f.read()
```

Therefore, we must fake a cookie that gives `is_admin=True`. Here is how the cookie session saved and loaded:

```python
import base64, binascii
import logging
import os

from flask.sessions import SessionMixin, SessionInterface
from flask import Flask, Response, Request

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from universalCRC import crc
from random import SystemRandom

import json

_logger = logging.getLogger(__name__)

class CustomSession(dict, SessionMixin):
    pass

class CustomSessionInterface(SessionInterface):

    _KEY_LENGTH = 32
    _BLOCK_LENGTH = 16
    _IV_LENGTH = _BLOCK_LENGTH
    _MAC_LENGTH = 8
    _POLY = [  # from the ECMA-182 standard
        62, 57, 55, 54, 53, 52, 47, 46, 45, 40, 39, 38, 37, 35, 33, 32, 31, 29,
        27, 24, 23, 22, 21, 19, 17, 13, 12, 10, 9, 7, 4, 1, 0,
    ]
    _POLY = sum(1 << d for d in _POLY)

    def __init__(self, key=None):
        self._random_generator = SystemRandom()
        if key is None:
            key = os.getenv("SECURE_SESSION_KEY")
        if key is None:
            key = self._random_generator.randbytes(self._KEY_LENGTH)
        else:
            key = base64.b64decode(key)
        self._key = key

    def open_session(self, app: Flask, request: Request):
        cookie = request.cookies.get(app.config["SESSION_COOKIE_NAME"])
        if cookie is None:
            return CustomSession()
        try:
            session_data = base64.b64decode(cookie)
            data = self._decrypt(session_data).decode("utf-8")
            return CustomSession(json.loads(data))
        except Exception as e:
            _logger.warning("failed to load session data: {}".format(e))
            return CustomSession()

    def save_session(
        self, app: Flask, session: SessionMixin, response: Response
    ) -> None:
        session_data = json.dumps(dict(session))
        data = self._encrypt(session_data.encode("utf-8"))
        response.set_cookie(app.config["SESSION_COOKIE_NAME"], base64.b64encode(data).decode("ascii"))

    def _encrypt(self, data: bytes):
        nonce = self._random_generator.randbytes(self._IV_LENGTH)
        cipher = Cipher(algorithms.AES(self._key), modes.CTR(nonce))
        encryptor = cipher.encryptor()
        mac = self._crc64(data)
        return nonce + encryptor.update(data + mac) + encryptor.finalize()

    def _decrypt(self, data: bytes):
        minimum_ciphertext_length = self._IV_LENGTH + self._MAC_LENGTH
        if len(data) < minimum_ciphertext_length:
            raise ValueError("ciphertext too short to decrypt, was {} bytes, at least {} required".format(
                len(data),
                minimum_ciphertext_length
            ))

        iv = data[0:self._IV_LENGTH]
        data = data[self._IV_LENGTH:]

        cipher = Cipher(algorithms.AES(self._key), modes.CTR(iv))
        decryptor = cipher.decryptor()
        data = decryptor.update(data) + decryptor.finalize()

        assert len(data) > self._MAC_LENGTH

        transmitted_mac = data[-self._MAC_LENGTH:]
        data = data[:-self._MAC_LENGTH]
        mac_of_received_data = self._crc64(data)
        if mac_of_received_data != transmitted_mac:
            raise ValueError("decryption failed: invalid MAC. Most likely someone has tampered with the transmitted data.")

        return data

    def _crc64(self, data):
        check_value = crc.compute_CRC(binascii.hexlify(data).decode("ascii"), self._POLY, 0, 0, 64, False, False)
        return check_value.to_bytes(8, "big")
```

The algorithm is:

1. Generate random key and IV
2. Encode session data to JSON
3. Append crc64 protecting the JSON
4. Encrypt JSON + crc64 using AES CTR mode

AES CTR works by encrypting `IV + counter` and XORs the result into plaintext:

```
AES-CTR-Encrypt(key, plaintext, iv, ctr) = AES-ECB-Encrypt(key, iv || ctr) xor plaintext
```

So we can change the decrypted plaintext into arbitrary text `arbitrary` by:

```
AES-CTR-Decrypt(key, AES-CTR-Encrypt(key, plaintext, iv, ctr) xor plaintext xor arbitrary, iv, ctr)
= AES-ECB-Encrypt(key, iv || ctr) xor AES-CTR-Encrypt(key, plaintext, iv, ctr) xor plaintext xor arbitrary
= AES-ECB-Encrypt(key, iv || ctr) xor AES-ECB-Encrypt(key, iv || ctr) xor plaintext xor plaintext xor arbitrary
= arbitrary
```

So the next thing is to break crc protection. There is a property of crc that:

```
CRC(x xor y) = CRC(x) xor CRC(y)
```

If x and y has the same length. Therefore, we only need to:

1. Find the format of the plaintext, e.g. `{"user_id": "62dd4d7e-2ef0-4515-849c-cc1d8bed5370", "is_admin": false}`, let's call it `x`
2. Choose our arbitrary text called `y`: `{"user_id": "62dd4d7e-2ef0-4515-849c-cc1d8bed5370", "is_admin": true }` that has the same length, but `"false"` becomes `"true "`, not the extra whitespace
3. Compute `x xor y`, and it should be xor-ed into AES-CTR encrypted data
4. Compute `crc(x xor y)`, and it should be xor-ed into the CRC

Proof of concept:

```python
import uuid
import json
from universalCRC import crc
import binascii
from random import SystemRandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_KEY_LENGTH = 32
_BLOCK_LENGTH = 16
_IV_LENGTH = _BLOCK_LENGTH
_MAC_LENGTH = 8
_POLY = [  # from the ECMA-182 standard
    62,
    57,
    55,
    54,
    53,
    52,
    47,
    46,
    45,
    40,
    39,
    38,
    37,
    35,
    33,
    32,
    31,
    29,
    27,
    24,
    23,
    22,
    21,
    19,
    17,
    13,
    12,
    10,
    9,
    7,
    4,
    1,
    0,
]
_POLY = sum(1 << d for d in _POLY)
_random_generator = SystemRandom()
_key = _random_generator.randbytes(_KEY_LENGTH)


def _crc64(data):
    check_value = crc.compute_CRC(
        binascii.hexlify(data).decode("ascii"), _POLY, 0, 0, 64, False, False
    )
    return check_value.to_bytes(8, "big")


def _encrypt(data: bytes):
    nonce = _random_generator.randbytes(_IV_LENGTH)
    cipher = Cipher(algorithms.AES(_key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    mac = _crc64(data)
    return nonce + encryptor.update(data + mac) + encryptor.finalize()


def _decrypt(data: bytes):
    minimum_ciphertext_length = _IV_LENGTH + _MAC_LENGTH
    if len(data) < minimum_ciphertext_length:
        raise ValueError(
            "ciphertext too short to decrypt, was {} bytes, at least {} required".format(
                len(data), minimum_ciphertext_length
            )
        )

    iv = data[0:_IV_LENGTH]
    data = data[_IV_LENGTH:]

    cipher = Cipher(algorithms.AES(_key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    data = decryptor.update(data) + decryptor.finalize()

    assert len(data) > _MAC_LENGTH

    transmitted_mac = data[-_MAC_LENGTH:]
    data = data[:-_MAC_LENGTH]
    mac_of_received_data = _crc64(data)
    if mac_of_received_data != transmitted_mac:
        raise ValueError(
            "decryption failed: invalid MAC. Most likely someone has tampered with the transmitted data."
        )

    return data


session_data = json.dumps(dict({"user_id": str(uuid.uuid4()), "is_admin": False}))
print(session_data)
data = _encrypt(session_data.encode("utf-8"))

# change "false" to "true "
xor_data = [ord(a) ^ ord(b) for a, b in zip("false", "true ")]
index = session_data.index("false")
xor_data = [0] * index + xor_data + [0]

# new data
data = bytearray(data)
for i in range(_IV_LENGTH, len(data) - _MAC_LENGTH):
    data[i] = data[i] ^ xor_data[i - _IV_LENGTH]
xor_mac = _crc64(bytes(xor_data))
# CRC(x xor y) = CRC(x) xor CRC(y)
for i in range(len(data) - _MAC_LENGTH, len(data)):
    data[i] = data[i] ^ xor_mac[i - (len(data) - _MAC_LENGTH)]
decrypted = _decrypt(data)
print(decrypted.decode())
```

Output:

```json
{"user_id": "657231d8-d647-4e92-a749-79880aacc8b4", "is_admin": false}
{"user_id": "657231d8-d647-4e92-a749-79880aacc8b4", "is_admin": true }
```

We have successfully passed the validation, while setting `is_admin` to `true`. Then, we only need to do the same thing online:

```python
import uuid
import json
from universalCRC import crc
import base64
import binascii

_BLOCK_LENGTH = 16
_IV_LENGTH = _BLOCK_LENGTH
_MAC_LENGTH = 8
_POLY = [  # from the ECMA-182 standard
    62,
    57,
    55,
    54,
    53,
    52,
    47,
    46,
    45,
    40,
    39,
    38,
    37,
    35,
    33,
    32,
    31,
    29,
    27,
    24,
    23,
    22,
    21,
    19,
    17,
    13,
    12,
    10,
    9,
    7,
    4,
    1,
    0,
]
_POLY = sum(1 << d for d in _POLY)


def _crc64(data):
    check_value = crc.compute_CRC(
        binascii.hexlify(data).decode("ascii"), _POLY, 0, 0, 64, False, False
    )
    return check_value.to_bytes(8, "big")


# the cookie is taken from the website
cookie = base64.b64decode("REDACTED")

session_data = json.dumps(dict({"user_id": str(uuid.uuid4()), "is_admin": False}))
data = cookie
# data = _encrypt(session_data.encode("utf-8"))

# change "false" to "true "
xor_data = [ord(a) ^ ord(b) for a, b in zip("false", "true ")]
index = session_data.index("false")
xor_data = [0] * index + xor_data + [0]

# new data
data = bytearray(data)
for i in range(_IV_LENGTH, len(data) - _MAC_LENGTH):
    data[i] = data[i] ^ xor_data[i - _IV_LENGTH]
xor_mac = _crc64(bytes(xor_data))
# CRC(x xor y) = CRC(x) xor CRC(y)
for i in range(len(data) - _MAC_LENGTH, len(data)):
    data[i] = data[i] ^ xor_mac[i - (len(data) - _MAC_LENGTH)]
print(base64.b64encode(data))
# decrypted = _decrypt(data)
# print(decrypted)
```

Then we can get flag using our crafted cookie:

```shell
curl http://52.59.124.14:5005/get-flag -H "Cookie: session=REDACTED"
ENO{null_1s_nu1l_d8683c9163965e2b}
```
