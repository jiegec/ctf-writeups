# mal medium

```
Can you trace the infection path and identify the C2 domain?

Source: mal_medium.zip
```

Find unique domains in the DNS log:

```shell
$ cat network.log | awk '{print $3;}' | sort | uniq
cdn.cloudflare.com
malicious-ops.secpen.net
ocsp.verisign.net
telemetry.microsoft.com
windowsupdate.com
```

Flag: `SPL{malicious-ops.secpen.net}`.
