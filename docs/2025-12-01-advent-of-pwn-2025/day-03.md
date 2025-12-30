# Day 03

Challenge script:

```shell
#!/bin/sh

set -eu

GIFT="$(cat /flag)"
rm /flag

touch /stocking

sleeping_nice() {
    ps ao ni,comm --no-headers \
        | awk '$1 > 0' \
        | grep -q sleep
}

# Only when children sleep sweetly and nice does Santa begin his flight
until sleeping_nice; do
    sleep 0.1
done

chmod 400 /stocking
printf "%s" "$GIFT" > /stocking
```

We can handle `sleeping_nice` check by running a sleep command using nice:

```shell
nice sleep 100
```

But we need to read the flag out, which is `chmod 400` later. However, the file remains the same. If we open it early and keep the file handle, we can read its content regardles of its permission:

```shell
ubuntu@2025~day-03:~$ tail -f /stocking
pwn.college{EeIeWi4nVDHtOxoSiYBvXZZWKzg.0FN4gTMywyM5EzN0EzW}^C
```

Steps:

1. run `tail -f /stocking`
2. run `nice sleep 100` in another terminal
3. find flag from the output of `tail`
