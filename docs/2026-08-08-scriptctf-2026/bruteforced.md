# Bruteforced

```
Help! Our website got bruteforced. Hopefully the attacker did not leak anything.
Attachments

    https://scriptctf-2026-wave1-randomchars-4f7d3a6b.s3.us-east-1.amazonaws.com/Forensics/Bruteforced/log.pcap

```

Filter by HTTP respsonse code:

```
http && http.response.code != 404
```

Only one URL succeeded in HTTP 200: `https://ctf.scriptsorcerers.xyz/flag_4919`. Visit it in the browser, and get flag in developer tools:

```html
<body class="bg-[#202028]">
    <div id="root">scriptCTF{7h3_h1dd3n_3ndp01n7_g0t_l34k3d}</div>
</body>
```
