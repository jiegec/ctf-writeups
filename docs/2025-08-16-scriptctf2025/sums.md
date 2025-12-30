# Sums

```
Find the sum of nums[i] for i in [l, r] (if there are any issues with input/output format, plz open a ticket)
```

Provided code:

```python
#!/usr/bin/env python3
import random
import subprocess
import sys
import time

start = time.time()

n = 123456

nums = [str(random.randint(0, 696969)) for _ in range(n)]

print(' '.join(nums), flush=True)

ranges = []
for _ in range(n):
    l = random.randint(0, n - 2)
    r = random.randint(l, n - 1)
    ranges.append(f"{l} {r}") #inclusive on [l, r] 0 indexed
    print(l, r)

big_input = ' '.join(nums) + "\n" + "\n".join(ranges) + "\n"

proc = subprocess.Popen(
    ['./solve'],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

stdout, stderr = proc.communicate(input=big_input)

out_lines = stdout.splitlines()
ans = [int(x) for x in out_lines[:n]]

urnums = []
for _ in range(n):
    urnums.append(int(input()))

if ans != urnums:
    print("wawawawawawawawawa")
    sys.exit(1)

if time.time() - start > 10:
    print("tletletletletletle")
    sys.exit(1)

print(open('flag.txt', 'r').readline())
```

Write the code in Rust:

```rust
use num_bigint::BigInt;

fn main() {
    let mut numbers = vec![];
    let n = 123456;
    for _ in 0..n {
        let i: i32 = text_io::read!();
        numbers.push(i);
    }
    let mut prefix_sums = vec![];
    prefix_sums.push(BigInt::from(numbers[0]));
    for i in 1..n {
        prefix_sums.push(BigInt::from(numbers[i]) + &prefix_sums[i - 1]);
    }
    eprintln!("Got numbers");
    for _ in 0..n {
        let l: i32 = text_io::read!();
        let r: i32 = text_io::read!();
        let mut bigint = prefix_sums[r as usize].clone();
        if l > 0 {
            bigint -= &prefix_sums[l as usize - 1];
        }
        println!("{}", bigint);
    }
    eprintln!("Finish");
    let s: String = text_io::read!();
    eprintln!("{}", s);
}
```

Run in a VPS for faster network:

```shell
$ time socat TCP:play.scriptsorcerers.xyz:10269 exec:./sums
Got numbers
Finish
scriptCTF{1_w4n7_m0r3_5um5_bb20d57ce421}

real    0m3.106s
user    0m0.377s
sys     0m0.549s
```
