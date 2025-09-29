# t0le t0le

```
Our CCDC business guy made a really weird inject. He's just obsessed with that damn cat... there's nothing hiding in there, right?
```

Extract the docx file as zip, we find a base64 in word/embeddings/oleObject1.bin: `Zmhhe2cweXJfZzB5cl96bF9vM3kwaTNxIX0=`.

Base64 decode:

```shell
$ echo "Zmhhe2cweXJfZzB5cl96bF9vM3kwaTNxIX0=" | base64 -d
fha{g0yr_g0yr_zl_o3y0i3q!}
```

Flag after rot13: `sun{t0le_t0le_my_b3l0v3d!}`.
