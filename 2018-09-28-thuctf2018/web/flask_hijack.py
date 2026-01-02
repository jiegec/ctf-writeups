secret_key = '!955)aa1~2.7e2ad'

from flask import (
    Flask,
    session)


app = Flask(__name__)
app.secret_key = secret_key

@app.route('/')
def hello_world():
    session["username"] = "admin" 

    print(session)
    return session["username"]
