# Insanity Check

```
Difficulty: Beginner
Author: OddNorseman

Our CTF page is pretty cool, right? Nom nom nom
```

Reading the Javascript code:

```javascript
  let g = [
    84, 68,  67, 88, 88,  83, 68, 77,  79,  6,  67, 105, 82, 7,
    82, 105, 7,  66, 23,  23, 23, 105, 88,  6,  65, 105, 66, 68,
    79, 105, 66, 6,  105, 2,  85, 66,  67,  2,  90, 90,  79, 105,
    70, 90,  2,  79, 105, 66, 94, 5,   105, 85, 66, 80,  75
  ];
  g = g.map(j => j ^ 54);
  function D() {
    if (o.current += 1, o.current == f) {
      const j = [ "al", "ert" ].join("");
      window[j](g.map(L => String.fromCharCode(L)).join(""))
    }
    c.current &&
        (o.current > f ? c.current.textContent = `Score: ${o.current}`
                       : c.current.textContent = `Score: ${o.current} / ${f} `);
    try {
      if (!S.current)
        return;
      const j = S.current.cloneNode(!0);
      try {
        j.play().then(() => {}).catch(L => {})
      } catch {
      }
    } catch (j) {
      console.warn("playHitSound error", j)
    }
  }
```

It prints the flag then the game succeeded. Print the flag directly:

```javascript
let g = [
  84, 68,  67, 88, 88,  83, 68, 77,  79,  6,  67, 105, 82, 7,
  82, 105, 7,  66, 23,  23, 23, 105, 88,  6,  65, 105, 66, 68,
  79, 105, 66, 6,  105, 2,  85, 66,  67,  2,  90, 90,  79, 105,
  70, 90,  2,  79, 105, 66, 94, 5,   105, 85, 66, 80,  75
];
g = g.map(j => j ^ 54);
g.map(L => String.fromCharCode(L)).join("")
```

Get flag: `brunner{y0u_d1d_1t!!!_n0w_try_t0_4ctu4lly_pl4y_th3_ctf}`