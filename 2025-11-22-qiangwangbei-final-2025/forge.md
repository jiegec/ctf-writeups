# forge

附件：

```python
from flask import Flask, request, jsonify, render_template, url_for, redirect
from functools import wraps
from ecdsa import SigningKey, SECP256k1
from hashlib import sha256
from random import shuffle, getrandbits, randint
from time import time_ns
import base64
import json
app = Flask(__name__)

with open("private.pem", 'rb') as f:
    pem_data = f.read()
    
sk = SigningKey.from_pem(pem_data)
vk = sk.verifying_key

kbits = 256
train_times = 1
ncount = 1

def get_nbits_k(nbits):
    while True:
        k = getrandbits(nbits)
        if k.bit_length() == nbits:
            return k
            
def verify_token(token):
    try:
        parts = token.split('.')
        if len(parts) != 2:
            return False

        msg = parts[0].encode()
        msg_digest = sha256(msg).digest()
        
        signature = base64.b64decode(parts[1])
        if vk.verify_digest(signature, msg_digest):
            return True
        else:
            return False
    except:
        return False
    

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'token' in request.cookies:
            try:
                token = request.cookies.get('token')
            except:
                return redirect(url_for('failure'))
        
        if not token:
            return redirect(url_for('failure'))
                
        valid = verify_token(token)

        if valid:
            parts = token.split('.')
            payload = parts[0]
            payload = base64.b64decode(payload)
            
            payload_json = json.loads(payload)
            request.user = payload_json["username"]
            return f(*args, **kwargs)
        else:
            return redirect(url_for('failure')) 
        
        
    
    return decorated
    
@app.route('/set_token', methods=['GET', 'POST'])
def set_token():
    if request.method == 'POST':
        token = request.form.get('token')
        response = redirect(url_for('welcome'))
        response.set_cookie('token', token, httponly=True, max_age=24*60*60)
        return response
    else:
        return render_template('set_token.html')
    

@app.route('/')
def index():
    return redirect(url_for('set_token'))    

@app.route('/welcome')
@token_required
def welcome():
    if request.user == "admin":
        return render_template('welcome.html')
    else:
        return redirect(url_for('guest')) 

@app.route('/failure')
def failure():
    return render_template('failure.html')

@app.route('/guest')
def guest():
    return render_template('guest.html')

@app.route('/api/pubkey', methods=['GET'])   
def pubkey():
    return jsonify({'vk': vk.to_string().hex()}), 200

 
@app.route('/api/set_param', methods=['POST'])
def set_param():
    global kbits, train_times, ncount
    print(sk.privkey.secret_multiplier)
    print(kbits, train_times, ncount)
    data = request.get_json()
    kbits = data.get('kbits')
    reason = ""
    if kbits < 240:
        kbits = 256
        reason = "kbits is too small"
    train_times = data.get('train')
    ncount = data.get('ncount')
    return jsonify({'status': 0, 'reason': reason}), 200

@app.route('/api/train', methods=['GET'])
def train():
    message = b"Not your keys, not your coins!"
    message_digest = sha256(message).digest()
    
    nonces = []
    for i in range(ncount):
        k = get_nbits_k(256)
        nonces.append(k)
        k = get_nbits_k(kbits)
        nonces.append(k)
    
    shuffle(nonces)
    
    costs = []
    sigs = []
    for k in nonces:
        tmp = 0
        for i in range(train_times):
            start = time_ns()
            signature = sk.sign_digest(message_digest, k=k)
            end = time_ns()
            tmp += end - start
        
        sigs.append(signature.hex())
        costs.append(tmp)
    
    return jsonify({'costs': costs, "sigs": sigs}), 200
    
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
```

这里的核心问题是，它使用了 [ecdsa](https://github.com/tlsfuzzer/python-ecdsa) 库来进行签名，而它是一个不防 timing side channel attack 的实现（见 [CVE-2024-23342](https://github.com/advisories/GHSA-wj6h-64fc-37mp)），本题正是如此。通过 `/api/set_param`，可以让服务器随机生产 240 位或 256 位的 nonce，然后根据时间的差异来判断它是 240 位还是 256 位的 nonce；如果得到一系列的 240 位的 nonce，就可以用 [cuso](https://github.com/keeganryan/cuso) 进行 [ecdsa known partial nonce attack](https://github.com/keeganryan/cuso/blob/main/examples/ecdsa_known_nonce_bits.py) 了，只不过这里知道的是 MSB（高 16 位都是 0），需要求解的就是低 240 位的 nonce 以及私钥。为了判断是 240 位还是 256 位的 nonce，这里用了一个比较粗暴的方法：生成大量的 signature，认为时间最短的那一个 signature 对应的是 240 位的 nonce。当然它不总是准确的，所以写了一个重试，如果 cuso 求解花费时间太长，就重来。可惜的是，即使本地打出来了，由于现场时间有限，还是没有拿到分数。

攻击代码：

```python
# need: sagemath, ecdsa, cuso from https://github.com/keeganryan/cuso
from hashlib import sha256
import json
import numpy as np
import ecdsa
import signal
from ecdsa.keys import _truncate_and_convert_digest
from ecdsa import SECP256k1
from ecdsa.util import sigdecode_string
from sage.all import var
import cuso
from pwn import *
import requests
import tqdm


url = "http://127.0.0.1:5000"  # CHANGEME


def handler(signum, frame):
    raise Exception("Timeout")


signal.signal(signal.SIGALRM, handler)

while True:
    n = int(SECP256k1.order)
    r = requests.post(
        f"{url}/api/set_param",
        json={
            "kbits": 240,
            "ncount": 1000,
            "train": 1,
        },
    )
    print(r)

    # get random numbers
    replys = []
    samples = []
    for i in tqdm.trange(10000):
        r = requests.get(
            f"{url}/api/train",
        )
        reply = r.json()
        replys.append(reply)
        print(reply)

        costs = reply["costs"]
        sigs = reply["sigs"]

        index = np.argmin(costs)
        sig = sigs[index]

        r, s = sigdecode_string(bytes.fromhex(sig), SECP256k1.order)
        samples += [(r, s)]

        if len(samples) == 17:
            break

    message = b"Not your keys, not your coins!"
    message_digest = sha256(message).digest()
    h = _truncate_and_convert_digest(message_digest, SECP256k1, True)

    # from cuso
    x = var("x")
    relations = []
    bounds = {x: (0, n)}
    for i, (r_i, s_i) in enumerate(samples):
        k_i_lsb = var(f"k_{i}_lsb")

        k_i = k_i_lsb

        # ECDSA equation s == k^-1 (h + rx)
        rel = s_i * k_i == h + r_i * x

        relations += [rel]
        bounds[k_i_lsb] = (0, 2**240)

    print("Got", len(samples), "samples")
    print("Solving, stop if it is too slow")
    # timeout 5s
    signal.alarm(5)
    try:
        roots = cuso.find_small_roots(
            relations=relations,
            bounds=bounds,
            modulus=n,
        )
        signal.alarm(0)
    except Exception:
        print("Timeout, retry")
        signal.alarm(0)
        continue
    x = roots[0][x]
    print(x)
    sk = ecdsa.SigningKey.from_secret_exponent(x, SECP256k1, hashfunc=hashlib.sha256)

    # forge
    msg = json.dumps({"username": "admin"}).encode()
    msg_digest = sha256(base64.b64encode(msg)).digest()
    signature = sk.sign_digest(msg_digest)
    cookie = f"{base64.b64encode(msg).decode()}.{base64.b64encode(signature).decode()}"
    print(msg, signature)
    r = requests.get(f"{url}/welcome", headers={"Cookie": f"token={cookie}"})
    print(r.text)
    print(f"Cookie: token={cookie}")
    break
```
