# Day 04

Attachment:

```c
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdbool.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

static volatile sig_atomic_t stop;

static void handle_sigint(int sig)
{
    (void)sig;
    stop = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *fmt, va_list args)
{
    return vfprintf(stderr, fmt, args);
}

static void broadcast_cheer(void)
{
    libbpf_set_print(libbpf_print_fn);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    DIR *d = opendir("/dev/pts");
    struct dirent *de;
    char path[64];
    char flag[256];
    char banner[512];
    ssize_t n;

    if (!d)
        return;

    int ffd = open("/flag", O_RDONLY | O_CLOEXEC);
    if (ffd >= 0) {
        n = read(ffd, flag, sizeof(flag) - 1);
        if (n >= 0)
            flag[n] = '\0';
        close(ffd);
    } else {
        strcpy(flag, "no-flag\n");
    }

    snprintf(
        banner,
        sizeof(banner),
        "🎅 🎄 🎁 \x1b[1;31mHo Ho Ho\x1b[0m, \x1b[1;32mMerry Christmas!\x1b[0m\n"
        "%s",
        flag);

    while ((de = readdir(d)) != NULL) {
        const char *name = de->d_name;
        size_t len = strlen(name);
        bool all_digits = true;

        if (len == 0 || name[0] == '.')
            continue;
        if (strcmp(name, "ptmx") == 0)
            continue;

        for (size_t i = 0; i < len; i++) {
            if (!isdigit((unsigned char)name[i])) {
                all_digits = false;
                break;
            }
        }
        if (!all_digits)
            continue;

        snprintf(path, sizeof(path), "/dev/pts/%s", name);
        int fd = open(path, O_WRONLY | O_NOCTTY | O_CLOEXEC);
        if (fd < 0)
            continue;
        write(fd, "\x1b[2J\x1b[H", 7);
        write(fd, banner, strlen(banner));
        close(fd);
    }

    closedir(d);
}

int main(void)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    struct bpf_map *success = NULL;
    int map_fd;
    __u32 key0 = 0;
    int err;
    int should_broadcast = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    setvbuf(stdout, NULL, _IONBF, 0);

    obj = bpf_object__open_file("/challenge/tracker.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        goto cleanup;
    }

    prog = bpf_object__find_program_by_name(obj, "handle_do_linkat");
    if (!prog) {
        fprintf(stderr, "Could not find BPF program handle_do_linkat\n");
        goto cleanup;
    }

    link = bpf_program__attach_kprobe(prog, false, "__x64_sys_linkat");
    if (!link) {
        fprintf(stderr, "Failed to attach kprobe __x64_sys_linkat: %s\n", strerror(errno));
        goto cleanup;
    }

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    success = bpf_object__find_map_by_name(obj, "success");
    if (!success) {
        fprintf(stderr, "Failed to find success map\n");
        goto cleanup;
    }
    map_fd = bpf_map__fd(success);

    printf("Attached. Press Ctrl-C to quit.\n");
    fflush(stdout);
    while (!stop) {
        __u32 v = 0;
        if (bpf_map_lookup_elem(map_fd, &key0, &v) == 0 && v != 0) {
            should_broadcast = 1;
            stop = 1;
            break;
        }
        usleep(100000);
    }

    if (should_broadcast)
        broadcast_cheer();

cleanup:
    if (link)
        bpf_link__destroy(link);
    if (obj)
        bpf_object__close(obj);
    return err ? 1 : 0;
}
```

It loads an eBPF program and waits for it `success` signal. We need to reverse engineer the eBPF bytecode:

```shell
bpf-objdump -d tracker.bpf.o > dump.S
```

With the assist of AI (see below), the bpf code hooked to `linkat` syscall does the following things:

1. validate the arguments
2. copy the two paths from the syscall arguments to ebpf local memory
3. compare the first path with "sleigh", fail if mismatch 
4. based on the current state in `progress` map, validate the second path with `dasher`, `dancer`, `prancer`, `vixen`, `comet`, `cupid`, `donner` and `blitzen` respectively
5. flag is given if all validation has passed

Experiment in privileged mode:

```shell
hacker@practice~2025~day-04:~$ sudo bpftool map list
1: array  name progress  flags 0x0
	key 4B  value 4B  max_entries 1  memlock 272B
	btf_id 12
2: array  name success  flags 0x0
	key 4B  value 4B  max_entries 1  memlock 272B
	btf_id 12
hacker@practice~2025~day-04:~$ sudo bpftool map dump id 1
[{
        "key": 0,
        "value": 0
    }
]
hacker@practice~2025~day-04:~$ ln sleigh dasher
ln: failed to create hard link 'dasher': File exists
hacker@practice~2025~day-04:~$ sudo bpftool map dump id 1
[{
        "key": 0,
        "value": 1
    }
]
hacker@practice~2025~day-04:~$ sudo bpftool map dump id 1
[{
        "key": 0,
        "value": 2
    }
]
```

It matches our expectation. So we run the following commands in unprivileged mode to get flag (launch tmux if via ssh):

```shell
ln sleigh dasher
ln sleigh dancer
ln sleigh prancer
ln sleigh vixen
ln sleigh comet
ln sleigh cupid
ln sleigh donner
ln sleigh blitzen
```

The annotated assembly:

```asm

tracker.bpf.o:     file format elf64-bpfle


Disassembly of section kprobe/__x64_sys_linkat:

0000000000000000 <handle_do_linkat>:
   0:	79 16 70 00 00 00 00 00 	ldxdw %r6,[%r1+112]
   8:	b7 01 00 00 00 00 00 00 	mov %r1,0
  10:	7b 1a d0 ff 00 00 00 00 	stxdw [%r10-48],%r1
  18:	7b 1a c8 ff 00 00 00 00 	stxdw [%r10-56],%r1
  20:	15 06 0e 01 00 00 00 00 	jeq %r6,0,270

# read argument to r10-48
  28:	bf 63 00 00 00 00 00 00 	mov %r3,%r6
  30:	07 03 00 00 68 00 00 00 	add %r3,104
  38:	bf a1 00 00 00 00 00 00 	mov %r1,%r10
  40:	07 01 00 00 d0 ff ff ff 	add %r1,-48
  48:	b7 02 00 00 08 00 00 00 	mov %r2,8
  50:	85 00 00 00 71 00 00 00 	call 113

# read argument to r10-56
  58:	07 06 00 00 38 00 00 00 	add %r6,56
  60:	bf a1 00 00 00 00 00 00 	mov %r1,%r10
  68:	07 01 00 00 c8 ff ff ff 	add %r1,-56
  70:	b7 02 00 00 08 00 00 00 	mov %r2,8
  78:	bf 63 00 00 00 00 00 00 	mov %r3,%r6
  80:	85 00 00 00 71 00 00 00 	call 113

  88:	79 a3 d0 ff 00 00 00 00 	ldxdw %r3,[%r10-48]
  90:	15 03 00 01 00 00 00 00 	jeq %r3,0,256
  98:	79 a1 c8 ff 00 00 00 00 	ldxdw %r1,[%r10-56]
  a0:	15 01 fe 00 00 00 00 00 	jeq %r1,0,254

# read string to r10-40
  a8:	bf a1 00 00 00 00 00 00 	mov %r1,%r10
  b0:	07 01 00 00 d8 ff ff ff 	add %r1,-40
  b8:	b7 02 00 00 10 00 00 00 	mov %r2,16
  c0:	85 00 00 00 72 00 00 00 	call 114
  c8:	67 00 00 00 20 00 00 00 	lsh %r0,32
  d0:	c7 00 00 00 20 00 00 00 	arsh %r0,32
  d8:	b7 01 00 00 01 00 00 00 	mov %r1,1
  e0:	6d 01 f6 00 00 00 00 00 	jsgt %r1,%r0,246

# read string to r10-16
  e8:	79 a3 d0 ff 00 00 00 00 	ldxdw %r3,[%r10-48]
  f0:	bf a1 00 00 00 00 00 00 	mov %r1,%r10
  f8:	07 01 00 00 f0 ff ff ff 	add %r1,-16
 100:	b7 02 00 00 10 00 00 00 	mov %r2,16
 108:	85 00 00 00 72 00 00 00 	call 114
 110:	67 00 00 00 20 00 00 00 	lsh %r0,32
 118:	77 00 00 00 20 00 00 00 	rsh %r0,32
 120:	55 00 ee 00 07 00 00 00 	jne %r0,7,238

# compare with "sleigh"
 128:	71 a1 f0 ff 00 00 00 00 	ldxb %r1,[%r10-16]
 130:	55 01 ec 00 73 00 00 00 	jne %r1,115,236
 138:	71 a1 f1 ff 00 00 00 00 	ldxb %r1,[%r10-15]
 140:	55 01 ea 00 6c 00 00 00 	jne %r1,108,234
 148:	71 a1 f2 ff 00 00 00 00 	ldxb %r1,[%r10-14]
 150:	55 01 e8 00 65 00 00 00 	jne %r1,101,232
 158:	71 a1 f3 ff 00 00 00 00 	ldxb %r1,[%r10-13]
 160:	55 01 e6 00 69 00 00 00 	jne %r1,105,230
 168:	71 a1 f4 ff 00 00 00 00 	ldxb %r1,[%r10-12]
 170:	55 01 e4 00 67 00 00 00 	jne %r1,103,228
 178:	71 a1 f5 ff 00 00 00 00 	ldxb %r1,[%r10-11]
 180:	55 01 e2 00 68 00 00 00 	jne %r1,104,226

 188:	79 a3 c8 ff 00 00 00 00 	ldxdw %r3,[%r10-56]
 190:	bf a1 00 00 00 00 00 00 	mov %r1,%r10
 198:	07 01 00 00 d8 ff ff ff 	add %r1,-40
 1a0:	b7 02 00 00 10 00 00 00 	mov %r2,16
 1a8:	85 00 00 00 72 00 00 00 	call 114
 1b0:	67 00 00 00 20 00 00 00 	lsh %r0,32
 1b8:	c7 00 00 00 20 00 00 00 	arsh %r0,32
 1c0:	b7 01 00 00 01 00 00 00 	mov %r1,1
 1c8:	6d 01 d9 00 00 00 00 00 	jsgt %r1,%r0,217
 1d0:	79 a6 c8 ff 00 00 00 00 	ldxdw %r6,[%r10-56]
 1d8:	b7 07 00 00 00 00 00 00 	mov %r7,0
 1e0:	63 7a ec ff 00 00 00 00 	stxw [%r10-20],%r7
 1e8:	bf a2 00 00 00 00 00 00 	mov %r2,%r10
 1f0:	07 02 00 00 ec ff ff ff 	add %r2,-20
 1f8:	18 01 00 00 00 00 00 00 	lddw %r1,0
 200:	00 00 00 00 00 00 00 00 
 208:	85 00 00 00 01 00 00 00 	call 1
 210:	15 00 01 00 00 00 00 00 	jeq %r0,0,1
 218:	61 07 00 00 00 00 00 00 	ldxw %r7,[%r0+0]
 220:	bf a1 00 00 00 00 00 00 	mov %r1,%r10
 228:	07 01 00 00 f0 ff ff ff 	add %r1,-16
 230:	b7 02 00 00 10 00 00 00 	mov %r2,16
 238:	bf 63 00 00 00 00 00 00 	mov %r3,%r6
 240:	85 00 00 00 72 00 00 00 	call 114
 248:	67 00 00 00 20 00 00 00 	lsh %r0,32
 250:	77 00 00 00 20 00 00 00 	rsh %r0,32
 258:	55 00 0e 00 07 00 00 00 	jne %r0,7,14

# compare with "dasher", set to 1
 260:	71 a1 f0 ff 00 00 00 00 	ldxb %r1,[%r10-16]
 268:	55 01 0c 00 64 00 00 00 	jne %r1,100,12
 270:	71 a1 f1 ff 00 00 00 00 	ldxb %r1,[%r10-15]
 278:	55 01 0a 00 61 00 00 00 	jne %r1,97,10
 280:	71 a1 f2 ff 00 00 00 00 	ldxb %r1,[%r10-14]
 288:	55 01 08 00 73 00 00 00 	jne %r1,115,8
 290:	71 a1 f3 ff 00 00 00 00 	ldxb %r1,[%r10-13]
 298:	55 01 06 00 68 00 00 00 	jne %r1,104,6
 2a0:	71 a1 f4 ff 00 00 00 00 	ldxb %r1,[%r10-12]
 2a8:	55 01 04 00 65 00 00 00 	jne %r1,101,4
 2b0:	71 a1 f5 ff 00 00 00 00 	ldxb %r1,[%r10-11]
 2b8:	55 01 02 00 72 00 00 00 	jne %r1,114,2
 2c0:	b7 01 00 00 01 00 00 00 	mov %r1,1
 2c8:	05 00 b0 00 00 00 00 00 	ja 176
 2d0:	65 07 18 00 03 00 00 00 	jsgt %r7,3,24
 2d8:	15 07 55 00 01 00 00 00 	jeq %r7,1,85
 2e0:	15 07 94 00 02 00 00 00 	jeq %r7,2,148
 2e8:	15 07 01 00 03 00 00 00 	jeq %r7,3,1
 2f0:	05 00 aa 00 00 00 00 00 	ja 170
 2f8:	bf a1 00 00 00 00 00 00 	mov %r1,%r10
 300:	07 01 00 00 f0 ff ff ff 	add %r1,-16
 308:	b7 02 00 00 10 00 00 00 	mov %r2,16
 310:	bf 63 00 00 00 00 00 00 	mov %r3,%r6
 318:	85 00 00 00 72 00 00 00 	call 114
 320:	67 00 00 00 20 00 00 00 	lsh %r0,32
 328:	77 00 00 00 20 00 00 00 	rsh %r0,32
 330:	55 00 a2 00 06 00 00 00 	jne %r0,6,162

# compare with "vixen", set to 4
 338:	71 a1 f0 ff 00 00 00 00 	ldxb %r1,[%r10-16]
 340:	55 01 a0 00 76 00 00 00 	jne %r1,118,160
 348:	71 a1 f1 ff 00 00 00 00 	ldxb %r1,[%r10-15]
 350:	55 01 9e 00 69 00 00 00 	jne %r1,105,158
 358:	71 a1 f2 ff 00 00 00 00 	ldxb %r1,[%r10-14]
 360:	55 01 9c 00 78 00 00 00 	jne %r1,120,156
 368:	71 a1 f3 ff 00 00 00 00 	ldxb %r1,[%r10-13]
 370:	55 01 9a 00 65 00 00 00 	jne %r1,101,154
 378:	71 a1 f4 ff 00 00 00 00 	ldxb %r1,[%r10-12]
 380:	55 01 98 00 6e 00 00 00 	jne %r1,110,152
 388:	b7 01 00 00 04 00 00 00 	mov %r1,4
 390:	05 00 97 00 00 00 00 00 	ja 151
 398:	65 07 17 00 05 00 00 00 	jsgt %r7,5,23
 3a0:	15 07 52 00 04 00 00 00 	jeq %r7,4,82
 3a8:	15 07 01 00 05 00 00 00 	jeq %r7,5,1
 3b0:	05 00 92 00 00 00 00 00 	ja 146
 3b8:	bf a1 00 00 00 00 00 00 	mov %r1,%r10
 3c0:	07 01 00 00 f0 ff ff ff 	add %r1,-16
 3c8:	b7 02 00 00 10 00 00 00 	mov %r2,16
 3d0:	bf 63 00 00 00 00 00 00 	mov %r3,%r6
 3d8:	85 00 00 00 72 00 00 00 	call 114
 3e0:	67 00 00 00 20 00 00 00 	lsh %r0,32
 3e8:	77 00 00 00 20 00 00 00 	rsh %r0,32
 3f0:	55 00 8a 00 06 00 00 00 	jne %r0,6,138

# compare with "cupid", set to 6
 3f8:	71 a1 f0 ff 00 00 00 00 	ldxb %r1,[%r10-16]
 400:	55 01 88 00 63 00 00 00 	jne %r1,99,136
 408:	71 a1 f1 ff 00 00 00 00 	ldxb %r1,[%r10-15]
 410:	55 01 86 00 75 00 00 00 	jne %r1,117,134
 418:	71 a1 f2 ff 00 00 00 00 	ldxb %r1,[%r10-14]
 420:	55 01 84 00 70 00 00 00 	jne %r1,112,132
 428:	71 a1 f3 ff 00 00 00 00 	ldxb %r1,[%r10-13]
 430:	55 01 82 00 69 00 00 00 	jne %r1,105,130
 438:	71 a1 f4 ff 00 00 00 00 	ldxb %r1,[%r10-12]
 440:	55 01 80 00 64 00 00 00 	jne %r1,100,128
 448:	b7 01 00 00 06 00 00 00 	mov %r1,6
 450:	05 00 7f 00 00 00 00 00 	ja 127
 458:	15 07 4f 00 06 00 00 00 	jeq %r7,6,79
 460:	15 07 01 00 07 00 00 00 	jeq %r7,7,1
 468:	05 00 7b 00 00 00 00 00 	ja 123
 470:	bf a1 00 00 00 00 00 00 	mov %r1,%r10
 478:	07 01 00 00 f0 ff ff ff 	add %r1,-16
 480:	b7 02 00 00 10 00 00 00 	mov %r2,16
 488:	bf 63 00 00 00 00 00 00 	mov %r3,%r6
 490:	85 00 00 00 72 00 00 00 	call 114
 498:	67 00 00 00 20 00 00 00 	lsh %r0,32
 4a0:	77 00 00 00 20 00 00 00 	rsh %r0,32
 4a8:	55 00 73 00 08 00 00 00 	jne %r0,8,115

# compare with "blitzen", finish
 4b0:	71 a1 f0 ff 00 00 00 00 	ldxb %r1,[%r10-16]
 4b8:	55 01 71 00 62 00 00 00 	jne %r1,98,113
 4c0:	71 a1 f1 ff 00 00 00 00 	ldxb %r1,[%r10-15]
 4c8:	55 01 6f 00 6c 00 00 00 	jne %r1,108,111
 4d0:	71 a1 f2 ff 00 00 00 00 	ldxb %r1,[%r10-14]
 4d8:	55 01 6d 00 69 00 00 00 	jne %r1,105,109
 4e0:	71 a1 f3 ff 00 00 00 00 	ldxb %r1,[%r10-13]
 4e8:	55 01 6b 00 74 00 00 00 	jne %r1,116,107
 4f0:	71 a1 f4 ff 00 00 00 00 	ldxb %r1,[%r10-12]
 4f8:	55 01 69 00 7a 00 00 00 	jne %r1,122,105
 500:	71 a1 f5 ff 00 00 00 00 	ldxb %r1,[%r10-11]
 508:	55 01 67 00 65 00 00 00 	jne %r1,101,103
 510:	71 a1 f6 ff 00 00 00 00 	ldxb %r1,[%r10-10]
 518:	55 01 65 00 6e 00 00 00 	jne %r1,110,101
 520:	b7 01 00 00 08 00 00 00 	mov %r1,8
 528:	63 1a e8 ff 00 00 00 00 	stxw [%r10-24],%r1
 530:	b7 01 00 00 01 00 00 00 	mov %r1,1
 538:	63 1a f0 ff 00 00 00 00 	stxw [%r10-16],%r1
 540:	bf a2 00 00 00 00 00 00 	mov %r2,%r10
 548:	07 02 00 00 ec ff ff ff 	add %r2,-20
 550:	bf a3 00 00 00 00 00 00 	mov %r3,%r10
 558:	07 03 00 00 f0 ff ff ff 	add %r3,-16
 560:	18 01 00 00 00 00 00 00 	lddw %r1,0
 568:	00 00 00 00 00 00 00 00 
 570:	b7 04 00 00 00 00 00 00 	mov %r4,0
 578:	85 00 00 00 02 00 00 00 	call 2
 580:	05 00 5a 00 00 00 00 00 	ja 90
 588:	bf a1 00 00 00 00 00 00 	mov %r1,%r10
 590:	07 01 00 00 f0 ff ff ff 	add %r1,-16
 598:	b7 02 00 00 10 00 00 00 	mov %r2,16
 5a0:	bf 63 00 00 00 00 00 00 	mov %r3,%r6
 5a8:	85 00 00 00 72 00 00 00 	call 114
 5b0:	67 00 00 00 20 00 00 00 	lsh %r0,32
 5b8:	77 00 00 00 20 00 00 00 	rsh %r0,32
 5c0:	55 00 50 00 07 00 00 00 	jne %r0,7,80

# compare with "dancer", set to 2
 5c8:	71 a1 f0 ff 00 00 00 00 	ldxb %r1,[%r10-16]
 5d0:	55 01 4e 00 64 00 00 00 	jne %r1,100,78
 5d8:	71 a1 f1 ff 00 00 00 00 	ldxb %r1,[%r10-15]
 5e0:	55 01 4c 00 61 00 00 00 	jne %r1,97,76
 5e8:	71 a1 f2 ff 00 00 00 00 	ldxb %r1,[%r10-14]
 5f0:	55 01 4a 00 6e 00 00 00 	jne %r1,110,74
 5f8:	71 a1 f3 ff 00 00 00 00 	ldxb %r1,[%r10-13]
 600:	55 01 48 00 63 00 00 00 	jne %r1,99,72
 608:	71 a1 f4 ff 00 00 00 00 	ldxb %r1,[%r10-12]
 610:	55 01 46 00 65 00 00 00 	jne %r1,101,70
 618:	71 a1 f5 ff 00 00 00 00 	ldxb %r1,[%r10-11]
 620:	55 01 44 00 72 00 00 00 	jne %r1,114,68
 628:	b7 01 00 00 02 00 00 00 	mov %r1,2
 630:	05 00 43 00 00 00 00 00 	ja 67
 638:	bf a1 00 00 00 00 00 00 	mov %r1,%r10
 640:	07 01 00 00 f0 ff ff ff 	add %r1,-16
 648:	b7 02 00 00 10 00 00 00 	mov %r2,16
 650:	bf 63 00 00 00 00 00 00 	mov %r3,%r6
 658:	85 00 00 00 72 00 00 00 	call 114
 660:	67 00 00 00 20 00 00 00 	lsh %r0,32
 668:	77 00 00 00 20 00 00 00 	rsh %r0,32
 670:	55 00 3a 00 06 00 00 00 	jne %r0,6,58

# compare with "comet", set to 5
 678:	71 a1 f0 ff 00 00 00 00 	ldxb %r1,[%r10-16]
 680:	55 01 38 00 63 00 00 00 	jne %r1,99,56
 688:	71 a1 f1 ff 00 00 00 00 	ldxb %r1,[%r10-15]
 690:	55 01 36 00 6f 00 00 00 	jne %r1,111,54
 698:	71 a1 f2 ff 00 00 00 00 	ldxb %r1,[%r10-14]
 6a0:	55 01 34 00 6d 00 00 00 	jne %r1,109,52
 6a8:	71 a1 f3 ff 00 00 00 00 	ldxb %r1,[%r10-13]
 6b0:	55 01 32 00 65 00 00 00 	jne %r1,101,50
 6b8:	71 a1 f4 ff 00 00 00 00 	ldxb %r1,[%r10-12]
 6c0:	55 01 30 00 74 00 00 00 	jne %r1,116,48
 6c8:	b7 01 00 00 05 00 00 00 	mov %r1,5
 6d0:	05 00 2f 00 00 00 00 00 	ja 47
 6d8:	bf a1 00 00 00 00 00 00 	mov %r1,%r10
 6e0:	07 01 00 00 f0 ff ff ff 	add %r1,-16
 6e8:	b7 02 00 00 10 00 00 00 	mov %r2,16
 6f0:	bf 63 00 00 00 00 00 00 	mov %r3,%r6
 6f8:	85 00 00 00 72 00 00 00 	call 114
 700:	67 00 00 00 20 00 00 00 	lsh %r0,32
 708:	77 00 00 00 20 00 00 00 	rsh %r0,32
 710:	55 00 26 00 07 00 00 00 	jne %r0,7,38

# compare with "donner", set to 7
 718:	71 a1 f0 ff 00 00 00 00 	ldxb %r1,[%r10-16]
 720:	55 01 24 00 64 00 00 00 	jne %r1,100,36
 728:	71 a1 f1 ff 00 00 00 00 	ldxb %r1,[%r10-15]
 730:	55 01 22 00 6f 00 00 00 	jne %r1,111,34
 738:	71 a1 f2 ff 00 00 00 00 	ldxb %r1,[%r10-14]
 740:	55 01 20 00 6e 00 00 00 	jne %r1,110,32
 748:	71 a1 f3 ff 00 00 00 00 	ldxb %r1,[%r10-13]
 750:	55 01 1e 00 6e 00 00 00 	jne %r1,110,30
 758:	71 a1 f4 ff 00 00 00 00 	ldxb %r1,[%r10-12]
 760:	55 01 1c 00 65 00 00 00 	jne %r1,101,28
 768:	71 a1 f5 ff 00 00 00 00 	ldxb %r1,[%r10-11]
 770:	55 01 1a 00 72 00 00 00 	jne %r1,114,26
 778:	b7 01 00 00 07 00 00 00 	mov %r1,7
 780:	05 00 19 00 00 00 00 00 	ja 25
 788:	bf a1 00 00 00 00 00 00 	mov %r1,%r10
 790:	07 01 00 00 f0 ff ff ff 	add %r1,-16
 798:	b7 02 00 00 10 00 00 00 	mov %r2,16
 7a0:	bf 63 00 00 00 00 00 00 	mov %r3,%r6
 7a8:	85 00 00 00 72 00 00 00 	call 114
 7b0:	67 00 00 00 20 00 00 00 	lsh %r0,32
 7b8:	77 00 00 00 20 00 00 00 	rsh %r0,32
 7c0:	55 00 10 00 08 00 00 00 	jne %r0,8,16

# compare with "prancer", set to 3
 7c8:	71 a1 f0 ff 00 00 00 00 	ldxb %r1,[%r10-16]
 7d0:	55 01 0e 00 70 00 00 00 	jne %r1,112,14
 7d8:	71 a1 f1 ff 00 00 00 00 	ldxb %r1,[%r10-15]
 7e0:	55 01 0c 00 72 00 00 00 	jne %r1,114,12
 7e8:	71 a1 f2 ff 00 00 00 00 	ldxb %r1,[%r10-14]
 7f0:	55 01 0a 00 61 00 00 00 	jne %r1,97,10
 7f8:	71 a1 f3 ff 00 00 00 00 	ldxb %r1,[%r10-13]
 800:	55 01 08 00 6e 00 00 00 	jne %r1,110,8
 808:	71 a1 f4 ff 00 00 00 00 	ldxb %r1,[%r10-12]
 810:	55 01 06 00 63 00 00 00 	jne %r1,99,6
 818:	71 a1 f5 ff 00 00 00 00 	ldxb %r1,[%r10-11]
 820:	55 01 04 00 65 00 00 00 	jne %r1,101,4
 828:	71 a1 f6 ff 00 00 00 00 	ldxb %r1,[%r10-10]
 830:	55 01 02 00 72 00 00 00 	jne %r1,114,2
 838:	b7 01 00 00 03 00 00 00 	mov %r1,3
 840:	05 00 01 00 00 00 00 00 	ja 1
 848:	b7 01 00 00 00 00 00 00 	mov %r1,0
 850:	63 1a e8 ff 00 00 00 00 	stxw [%r10-24],%r1
 858:	bf a2 00 00 00 00 00 00 	mov %r2,%r10
 860:	07 02 00 00 ec ff ff ff 	add %r2,-20
 868:	bf a3 00 00 00 00 00 00 	mov %r3,%r10
 870:	07 03 00 00 e8 ff ff ff 	add %r3,-24
 878:	18 01 00 00 00 00 00 00 	lddw %r1,0
 880:	00 00 00 00 00 00 00 00 
 888:	b7 04 00 00 00 00 00 00 	mov %r4,0
 890:	85 00 00 00 02 00 00 00 	call 2
 898:	b7 00 00 00 00 00 00 00 	mov %r0,0
 8a0:	95 00 00 00 00 00 00 00 	exit

# order:
ln sleigh dasher
ln sleigh dancer
ln sleigh prancer
ln sleigh vixen
ln sleigh comet
ln sleigh cupid
ln sleigh donner
ln sleigh blitzen
```

## DeepSeek

The following analysis is done by DeepSeek:

Looking at this BPF assembly code for the `handle_do_linkat` function attached to `__x64_sys_linkat`, I can see it's implementing a complex state machine that appears to be checking for specific paths in the `linkat` system call and performing a series of string comparisons.

### Key Analysis:

1. **Path String Extraction**: The code reads two path strings from the linkat arguments:
   - First string loaded from `[%r1+112]` (old path)
   - Second string loaded from `[%r1+70]` (new path)

2. **String Matching Logic**: The code performs sequential string comparisons:
   - First checks if the path is "sleigh" (bytes: 115, 108, 101, 105, 103, 104)
   - Then checks various other strings like "dasher", "vixen", "comet", "cupid", "dancer", "prancer", "blitzen", etc.

3. **State Machine**: The code uses `%r7` as a state variable and implements what appears to be a sequence of required paths. It checks for different strings based on the current state.

4. **Success Condition**: The code sets up values and calls helper functions (call 1 and call 2) which are likely `bpf_map_lookup_elem` and `bpf_map_update_elem`. When the correct sequence is followed, it should update a map that the C program is monitoring.

### Required Link Call:

To trigger the success condition and cause `broadcast_cheer()` to be called, you need to call the `linkat` system call with specific paths that satisfy the state machine. Based on the string comparisons, it seems you need to create hard links with specific names.

**The simplest approach** would be to try creating a hard link from a source named "sleigh" to a destination named "dasher":

```bash
# Create the source file
touch /tmp/sleigh

# Make the linkat system call
linkat(AT_FDCWD, "/tmp/sleigh", AT_FDCWD, "/tmp/dasher", 0)
```

Or using the command line:
```bash
ln /tmp/sleigh /tmp/dasher
```

### Alternative Approach:

The BPF program appears to be implementing a Christmas-themed challenge where you need to link "sleigh" to various reindeer names in sequence. You might need to make multiple calls with different destination names to progress through the state machine.

Given the complexity, you might need to try:
1. `linkat(..., "sleigh", ..., "dasher", ...)`
2. `linkat(..., "sleigh", ..., "vixen", ...)`
3. `linkat(..., "sleigh", ..., "comet", ...)`
...and so on through the sequence of reindeer names found in the assembly.

### How to Test:

You can use a simple C program to make the syscall directly:

```c
#include <fcntl.h>
#include <unistd.h>

int main() {
    // Create source file
    int fd = open("/tmp/sleigh", O_CREAT | O_RDWR, 0644);
    close(fd);
    
    // Make the linkat syscall
    syscall(SYS_linkat, AT_FDCWD, "/tmp/sleigh", AT_FDCWD, "/tmp/dasher", 0);
    
    return 0;
}
```

**Note**: The exact behavior depends on the full state machine implemented in the BPF code, which tracks state in a BPF map. You may need to make multiple calls with different destination names to satisfy all the conditions.
