# permpress

```
Written by virchau13

It's kinda like doing your laundry, if you think about it hard enough.
nc challs.watctf.org 2333 
```

Attachment:

```rs
use rand::{seq::SliceRandom, Rng};
use rustc_hash::FxBuildHasher;
use std::{hash::{BuildHasher, Hash}, io::{self, BufRead, Read, Write}};
use simplehash::fnv1a_64;

fn do_hash(x: i32) -> u64 {
    fnv1a_64(&x.to_le_bytes())
}

const HASH_SIZE: usize = 32;

fn test_perm_restricted_memory(perm: &[i32]) -> bool {
    let mut map = [-1i32; HASH_SIZE];
    for x in perm {
        let idx = (do_hash(*x) % HASH_SIZE as u64) as usize;
        if map[idx] == *x {
            // duplicate, fail
            return false;
        } else {
            // not a duplicate, continue
        }
        map[idx] = *x;
    }
    true
}

fn parse_perm(inp: &str) -> Result<Vec<i32>, &'static str> {
    let ans: Vec<i32> = inp.trim().split(' ').map(|x| x.parse::<u32>().unwrap() as i32).collect();
    if ans.len() != 256 {
        return Err("permutation is not of length 256");
    }
    for x in &ans {
        if *x < 0 || 256 <= *x {
            return Err("permutation element out of range");
        }
    }
    if !test_perm_restricted_memory(&ans) {
        return Err("permutation has non-unique elements");
    }
    Ok(ans)
}

fn compose_perms(p1: &[i32], p2: &[i32]) -> Vec<i32> {
    p1.iter().map(|i| p2[*i as usize]).collect()
}

fn main() {
    let mut rng = rand::rng();
    let mut cipherperm: Vec<i32> = (0..256).collect();
    cipherperm.shuffle(&mut rng);
    let stdin = io::stdin();
    let mut line_iter = stdin.lock().lines();
    let mut get_line = || -> String {
        line_iter.next().unwrap().unwrap()
    };
    println!("Welcome to the Permutation Oracle.");
    loop {
        println!("Main Menu");
        println!("1. Give the oracle a permutation");
        println!("2. Guess the secret permutation");
        print!("Enter your choice: ");
        io::stdout().flush().unwrap();
        let choice = get_line();
        let choice: u32 = choice.trim().parse().unwrap();
        if choice == 1 {
            print!("Enter the permutation seperated by spaces: ");
            io::stdout().flush().unwrap();
            let perm_str = get_line();
            let perm = match parse_perm(&perm_str) {
                Err(e) => {
                    println!("Error: {e}");
                    continue;
                },
                Ok(v) => v,
            };
            let res = compose_perms(&perm, &cipherperm);
            let i = rng.random_range(0..res.len());
            println!("The oracle has divined... {}", res[i]);
        } else if choice == 2 {
            print!("Enter the permutation seperated by spaces: ");
            io::stdout().flush().unwrap();
            let perm_str = get_line();
            let perm = match parse_perm(&perm_str) {
                Err(e) => {
                    println!("Error: {e}");
                    continue;
                },
                Ok(v) => v,
            };
            if perm == cipherperm {
                println!("Good job! Here's your reward: {}", std::env::var("FLAG").unwrap());
            } else {
                println!("Unfortunately, wrong :/");
            }
        }
    }
}
```

We can send a permutation of `0..256` to the server, then the server combines the permutation with the oracle and responds with a random element. However, the validation is buggy:

```rust
fn test_perm_restricted_memory(perm: &[i32]) -> bool {
    let mut map = [-1i32; HASH_SIZE];
    for x in perm {
        let idx = (do_hash(*x) % HASH_SIZE as u64) as usize;
        if map[idx] == *x {
            // duplicate, fail
            return false;
        } else {
            // not a duplicate, continue
        }
        map[idx] = *x;
    }
    true
}
```

If we send two values that map to the same bucket in turns, it does not report duplication. So, firstly we need to find the values that belong to the same bucket:

```rust
use rand::{seq::SliceRandom, Rng};
use rustc_hash::FxBuildHasher;
use simplehash::fnv1a_64;
use std::{
    hash::{BuildHasher, Hash},
    io::{self, BufRead, Read, Write},
};

fn do_hash(x: i32) -> u64 {
    fnv1a_64(&x.to_le_bytes())
}

const HASH_SIZE: usize = 32;
fn main() {
    let mut buckets = vec![vec![]; HASH_SIZE];
    for i in 0..256 {
        let idx = (do_hash(i) % HASH_SIZE as u64) as usize;
        buckets[idx].push(i);
    }
    for i in 0..HASH_SIZE {
        println!("{}: {:?}", i, buckets[i]);
    }
}
```

Then, we can generate a sequence of `e1, e2, e1, e2, ...` to get either `oracle[e1]` or `oracle[e2]`. Then, we can use `e1, e3, e1, e3, ...` to get either `oracle[e1]` or `oracle[e3]`. The intersection will be `oracle[e2]`. Continue the process until we find all elements.

Attack script:

```python
from pwn import *

context(log_level="debug")

buckets = {
    0: [5, 37, 69, 101, 133, 165, 197, 229],
    1: [20, 52, 84, 116, 148, 180, 212, 244],
    2: [7, 39, 71, 103, 135, 167, 199, 231],
    3: [22, 54, 86, 118, 150, 182, 214, 246],
    4: [1, 33, 65, 97, 129, 161, 193, 225],
    5: [16, 48, 80, 112, 144, 176, 208, 240],
    6: [3, 35, 67, 99, 131, 163, 195, 227],
    7: [18, 50, 82, 114, 146, 178, 210, 242],
    8: [13, 45, 77, 109, 141, 173, 205, 237],
    9: [28, 60, 92, 124, 156, 188, 220, 252],
    10: [15, 47, 79, 111, 143, 175, 207, 239],
    11: [30, 62, 94, 126, 158, 190, 222, 254],
    12: [9, 41, 73, 105, 137, 169, 201, 233],
    13: [24, 56, 88, 120, 152, 184, 216, 248],
    14: [11, 43, 75, 107, 139, 171, 203, 235],
    15: [26, 58, 90, 122, 154, 186, 218, 250],
    16: [21, 53, 85, 117, 149, 181, 213, 245],
    17: [4, 36, 68, 100, 132, 164, 196, 228],
    18: [23, 55, 87, 119, 151, 183, 215, 247],
    19: [6, 38, 70, 102, 134, 166, 198, 230],
    20: [17, 49, 81, 113, 145, 177, 209, 241],
    21: [0, 32, 64, 96, 128, 160, 192, 224],
    22: [19, 51, 83, 115, 147, 179, 211, 243],
    23: [2, 34, 66, 98, 130, 162, 194, 226],
    24: [29, 61, 93, 125, 157, 189, 221, 253],
    25: [12, 44, 76, 108, 140, 172, 204, 236],
    26: [31, 63, 95, 127, 159, 191, 223, 255],
    27: [14, 46, 78, 110, 142, 174, 206, 238],
    28: [25, 57, 89, 121, 153, 185, 217, 249],
    29: [8, 40, 72, 104, 136, 168, 200, 232],
    30: [27, 59, 91, 123, 155, 187, 219, 251],
    31: [10, 42, 74, 106, 138, 170, 202, 234],
}

oracle = [0] * 256

p = remote("challs.watctf.org", 2333)
# p = process("./target/debug/permpress")

for i in buckets:
    bucket = buckets[i]
    # alternate between pairs
    for j in range(0, len(bucket), 2):
        e1 = bucket[j]
        e2 = bucket[j + 1]
        values = set()
        while len(values) < 2:
            p.recvuntil(b"Enter your choice:")
            p.sendline(b"1")
            p.recvuntil(b"spaces: ")
            p.sendline(" ".join([str(e1), str(e2)] * 128).encode())
            result = p.recvline()
            value = int(result.split()[-1])
            values.add(value)
            print(value)

        # we know that {oracle[e1], oracle[e2]} == values
        # but we don't know the order
        e3 = bucket[(j + 2) % len(bucket)]
        values2 = set()
        while len(values2) < 2:
            p.recvuntil(b"Enter your choice:")
            p.sendline(b"1")
            p.recvuntil(b"spaces: ")
            p.sendline(" ".join([str(e1), str(e3)] * 128).encode())
            result = p.recvline()
            value = int(result.split()[-1])
            values2.add(value)

        # the intersection of values and values2 is oracle[e1]
        oracle[e1] = (values & values2).pop()
        oracle[e2] = (values - set([oracle[e1]])).pop()
    print(oracle)

p.recvuntil(b"Enter your choice:")
p.sendline(b"2")
p.recvuntil(b"spaces: ")
p.sendline(" ".join([str(e) for e in oracle]).encode())
p.interactive()
```

Flag: `watctf{1nd1v1du4l_p3rm5_l0v3_uniqueness}`.
