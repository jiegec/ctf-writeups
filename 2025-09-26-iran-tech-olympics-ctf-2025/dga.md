# DGA

```
Our network is infected with DGA botnets. To block future malicious domains preemptively, we need to predict their behavior. The next domain generated will be asis.FLAG.com. Submit the flag in the format ASIS{FLAG}.
```

Print all the domains in the `log.json`:

```python
import json

data = json.load(open("log.json"))
i = 0
for entry in data[1:]:
    if "http" in entry:
        print(i, entry["http"]["address"])
        i += 1
```

Output:

```
0 xcac.uyhrssogelhaijhfns.com
1 xcsc.uyersaoghlhsijefna.com
2 xclc.uylrslogllhlijlfnl.com
3 xcec.uyarshogslheijafnh.com
4 xcwc.uywrswogwlhwijwfnw.com
5 xcpc.uyersaoghlhsijefna.com
6 xcic.uysrseogalhhijsfne.com
7 xcbc.uyhrssogelhaijhfns.com
8 xeae.udhrbsoweloaixhfqs.com
9 xese.uderbaowhlosixefqa.com
// ...
237 aqpq.wcetyaqshngskhehja.com
238 aqiq.wcstyeqsanghkhshje.com
239 aqbq.wchtysqsengakhhhjs.com
```

Following the patterns, the next domain starting with `asis` is:

```
246 asis.wgstheqjannhkvshme.com
```

Flag: `ASIS{wgstheqjannhkvshme}`.
