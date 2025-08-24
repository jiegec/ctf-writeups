# The Secret Brunsviger

```
Difficulty: Beginner
Author: Ha1fdan

I have intercepted encrypted HTTPS traffic from the secret brunsviger baking forum, but I need help decrypting it.
```

Following <https://wiki.wireshark.org/TLS>, we can inject the given TLS key into the pcap:

```shell
$ editcap --inject-secrets tls,keys.log traffic.pcap output.pcap
```

Open `output.pcap` in Wireshark, found the following HTTP response:

```
GET /api/messages/9 HTTP/1.1
Host: 127.0.0.1:4443
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br, zstd
Referer: https://127.0.0.1:4443/
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=4


HTTP/1.1 200 OK
Server: Werkzeug/3.1.3 Python/3.10.12
Date: Mon, 17 Mar 2025 20:47:29 GMT
Content-Type: application/json
Content-Length: 164
Connection: close

{
  "id": 9,
  "text": "Here's the secret recipe: YnJ1bm5lcntTM2NyM3RfQnJ1bnp2MWczcl9SM2MxcDNfRnIwbV9HcjRuZG00c19DMDBrYjAwa30=",
  "user": "Baking master Jensen"
}
```

Decoding the base64 leads to: `brunner{S3cr3t_Brunzv1g3r_R3c1p3_Fr0m_Gr4ndm4s_C00kb00k}`
