# Lunar Auth

```
Infiltrate the LunarAuth admin panel and gain access to the super secret FLAG artifact !
https://comet.sunshinectf.games 
```

Visit `/robots.txt`:

```
# tired of these annoying search engine bots scraping the admin panel page logins:

Disallow: /admin
```

Visit `/admin`:

```js
    const real_username = atob("YWxpbXVoYW1tYWRzZWN1cmVk");
    const real_passwd   = atob("UzNjdXI0X1BAJCR3MFJEIQ==");
```

Print `real_username` and `real_passwd` in console:

```
>> real_username
"alimuhammadsecured"
>> real_passwd
"S3cur4_P@$$w0RD!" 
```

Use the credentials to get flag
Flag: `sun{cl1ent_s1d3_auth_1s_N3V3R_a_g00d_1d3A_983765367890393232}`.
