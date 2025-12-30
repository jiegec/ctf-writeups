# Pretty Delicious Food

```
This cake is out of this world! :DDDDDDD

omnomonmonmonmonm

...

something else is out of place too.

Note: This is not a steganography challenge
```

Decompress the pdf using qpdf:

```shell
qpdf --qdf prettydeliciouscakes.pdf temp.pdf
```

In the decompressed pdf:

```javascript
const data = 'c3Vue3AzM3BfZDFzX2ZsQGdfeTAhfQ==';
```

Decode the base64 to get flag: `sun{p33p_d1s_fl@g_y0!}`.
