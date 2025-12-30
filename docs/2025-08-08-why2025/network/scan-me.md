# Scan Me

Find hint at port 65534:

```shell
$ nc scanme.ctf.zone 65534
Use the order of ports for the order of the flag!
```

`nc` to some ports provides one-character, e.g. `nc scanme.ctf.zone 18395` gives `0`.

Get characters in parallel in fish shell:

```fish
for port in (seq 1024 65535)
    nc scanme.ctf.zone $port > nc-$port.txt &
end;
cat nc-*.txt
```

Solved!
