# Captcha 2.0

A pcap file is provided recording a SQL injection attack. The attack uses two types of injection:

- `"user" = "test' AND (SELECT SUBSTR(sql,17,1) FROM  SQLITE_MASTER LIMIT 0,1) = 'r"` to probe the sql byte per byte
- `"user" = "test' AND (SELECT SUBSTR(password,38,1)  FROM userTable LIMIT 0,1) = '}"` to probe the password byte per byte

If injection succeeds, there is HTTP 304 to redirect to the homepage. We just need to find all these redirects and locate the corresponding injection query:

```python
import pyshark

cap = pyshark.FileCapture("captcha-2.0.pcap", display_filter="http")
last = None
for pkt in cap:
    s = str(pkt)
    if "302 Found" in s:
        if last is not None:
            print(last)
            last = None
    if "SELECT SUBSTR" in s:
        for line in s.splitlines():
            if "SELECT SUBSTR" in line:
                last = line
                break
```

This gives the SQL `CREATE TABLE userTable (userName varchar(8),password varchar(40))` and password `flag{caf496dfaa234481be31002ccf1dffb4}`.

Solved!
