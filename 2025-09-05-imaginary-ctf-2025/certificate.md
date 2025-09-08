# certificate

```
by Eth007
Description

As a thank you for playing our CTF, we're giving out participation certificates! Each one comes with a custom flag, but I bet you can't get the flag belonging to Eth007!

https://eth007.me/cert/
```

Visiting the website, we can find its source code:

```js
function customHash(str) {
  let h = 1337;
  for (let i = 0; i < str.length; i++) {
    h = (h * 31 + str.charCodeAt(i)) ^ (h >>> 7);
    h = h >>> 0; // force unsigned
  }
  return h.toString(16);
}
function makeFlag(name) {
  const clean = name.trim() ||
  'anon';
  const h = customHash(clean);
  return `ictf{${ h }}`;
}

function renderPreview() {
  var name = nameInput.value.trim();
  if (name == 'Eth007') {
    name = 'REDACTED'
  }
  const svg = buildCertificateSVG({
    participant: name ||
    'Participant Name',
    affiliation: affInput.value.trim() ||
    'Participant',
    date: dateInput.value,
    styleKey: styleSelect.value
  });
  svgHolder.innerHTML = svg;
  svgHolder.dataset.currentSvg = svg;
}
```

We can simply get flag by calling `makeFlag` directly:

```
>> makeFlag("Eth007")
"ictf{7b4b3965}" 
```
