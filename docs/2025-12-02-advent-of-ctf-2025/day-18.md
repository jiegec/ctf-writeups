# Day 18 Sealed for Delivery

Attachment:

```python
#!/usr/local/bin/python3
from Crypto.Util.number import getPrime, isPrime
from secrets import randbelow, token_urlsafe
from string import printable
from secret import FLAG
import json
import time

p = 0
while not isPrime(p // 2):
    p = getPrime(257)

g = randbelow(p)
if pow(g, p // 2, p) != 1:
    g = p - g

s = randbelow(1 << 256)

user_len = 32
user_len_bytes = 3 * user_len // 4

def mac(m, s=s):
    m = int.from_bytes(m)
    res = pow(g, m ^ s, p)
    if res > p // 2:
        res = p - res
    return int.to_bytes(res, 32)

def gen_token(username):
    info = compress(username) + int.to_bytes(int(time.time() + 300), 32 - user_len_bytes)
    return info.hex(), mac(info).hex()

def verify_token(username, info, _mac):
    try:
        info = bytes.fromhex(info)
        _mac = bytes.fromhex(_mac)
    except ValueError:
        return False
    if mac(info) != _mac:
        return False
    if compress(username) != info[:user_len_bytes]:
        return False
    if int.from_bytes(info[user_len_bytes:]) < time.time():
        return False
    if username not in login:
        return False
    return True

def compress(username):
    return int.to_bytes(sum(chars.index(char) << (6 * i) for i, char in enumerate(username.rjust(user_len, "_"))), user_len_bytes)

chars = printable[:62] + "-_"

login = {"admin": token_urlsafe()}
data = {"admin": FLAG}

out = "awaiting query"
msg = {}

while True:
    msg["out"] = out
    print(json.dumps(msg))
    msg = {}
    out = ""
    try:
        query = json.loads(input())
    except json.decoder.JSONDecodeError:
        out = "invalid json"
        continue
    if "option" not in query:
        out = "no option selected"
        continue
    match query["option"]:
        case "register":
            if "username" in query and "password" in query \
            and type(query["username"]) == type(query["password"]) == str \
            and all(char in chars for char in query["username"]) \
            and query["username"][:1] in [*chars[:62]] \
            and len(query["username"]) <= user_len:
                if query["username"] not in login:
                    if "data" in query and type(query["data"]) == str:
                        login[query["username"]] = query["password"]
                        data[query["username"]] = query["data"]
                        out = "registered"
                    else:
                        out = "invalid data"
                else:
                    out = "username taken"
            else:
                out = "invalid credentials"
        case "login":
            if "username" in query and "password" in query \
            and type(query["username"]) == type(query["password"]) == str:
                if login.get(query["username"]) == query["password"]:
                    out = "logged in"
                    msg["info"], msg["mac"] = gen_token(query["username"])
                else:
                    out = "login failed"
            else:
                out = "invalid credentials"
        case "read":
            if "username" in query and "info" in query and "mac" in query \
            and type(query["username"]) == type(query["info"]) == type(query["mac"]) == str:
                if verify_token(query["username"], query["info"], query["mac"]):
                    out = "data read"
                    msg["data"] = data[query["username"]]
                else:
                    out = "invalid token"
            else:
                out = "invalid read query"
        case _:
            out = "invalid option"
```

If we are given `p` and `g`, we can forge mac by:

1. registering as `dmin` user, so the compressed user name has only one byte in differ
2. bruteforce the byte in the user name until `m ^ s` matches

PoC:

```python
import json
import subprocess
import sys
from string import printable
from Crypto.Util.number import bytes_to_long, long_to_bytes

chars = printable[:62] + "-_"
user_len = 32
user_len_bytes = 3 * user_len // 4


def compress(username):
    return int.to_bytes(
        sum(
            chars.index(char) << (6 * i)
            for i, char in enumerate(username.rjust(user_len, "_"))
        ),
        user_len_bytes,
    )


def exploit_local():
    print("Running working exploit on local test...")

    # Start test challenge
    proc = subprocess.Popen(
        [sys.executable, "test_chall.py"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    # Read initial output
    init_line = proc.stdout.readline().strip()

    def send_query(query):
        proc.stdin.write(json.dumps(query) + "\n")
        proc.stdin.flush()
        response = proc.stdout.readline().strip()
        return json.loads(response)

    # Get parameters from test_chall.py (we know them for local test)
    p = 139549164742089371365258993757536467189752262117715327226370716010970940043479
    g = 75209479086935240210155400547996066066973670405014719047294511839304427271354

    # Register and login as 'dmin'
    query = {
        "option": "register",
        "username": "dmin",
        "password": "pass",
        "data": "test",
    }
    resp = send_query(query)
    print(f"Register 'dmin': {resp.get('out')}")

    if resp.get("out") != "registered":
        print("Failed")
        proc.terminate()
        return

    # Login as 'dmin'
    query = {"option": "login", "username": "dmin", "password": "pass"}
    resp = send_query(query)
    print(f"Login 'dmin': {resp.get('out')}")

    if resp.get("out") != "logged in":
        print("Failed")
        proc.terminate()
        return

    info_dmin = resp["info"]
    mac_dmin = resp["mac"]

    print(f"\nGot token for 'dmin'")

    # Parse info_dmin
    info_dmin_bytes = bytes.fromhex(info_dmin)
    timestamp_bytes = info_dmin_bytes[user_len_bytes:]

    # Construct info_admin with same timestamp
    admin_comp = compress("admin")
    info_admin_bytes = admin_comp + timestamp_bytes
    info_admin = info_admin_bytes.hex()

    print(f"Constructed info_admin")

    # Convert mac_dmin to integer
    mac_dmin_bytes = bytes.fromhex(mac_dmin)
    mac_dmin_int = bytes_to_long(mac_dmin_bytes)

    # Compute d = i << 224
    # We need g^d
    for i in range(256):
        d = i << 224
        g_d = pow(g, d, p)

        # Compute mac_admin = mac_dmin * g^d mod p
        mac_admin_int = (mac_dmin_int * g_d) % p

        # Apply canonicalization if needed
        if mac_admin_int > p // 2:
            mac_admin_int = p - mac_admin_int

        mac_admin_hex = int.to_bytes(mac_admin_int, 32).hex()

        print(f"\nTrying forged token...")
        query = {
            "option": "read",
            "username": "admin",
            "info": info_admin,
            "mac": mac_admin_hex,
        }
        resp = send_query(query)

        if resp.get("out") == "data read":
            print(f"SUCCESS!")
            print(f"Got data: {resp.get('data')}")
            proc.terminate()
            return resp.get("data")
        else:
            print(f"Failed: {resp.get('out')}")


if __name__ == "__main__":
    result = exploit_local()
    if result:
        print(f"\n=== LOCAL EXPLOIT SUCCESS ===")
        print(f"Flag: {result}")
    else:
        print("\n=== LOCAL EXPLOIT FAILED ===")
```

However, the remaining problem is, how to find `p` and `q`.
