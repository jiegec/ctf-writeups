# Nintendo-SSwitch

```
Just get the flag dummy.

To connect, spawn an instance then run

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ProxyCommand='openssl s_client -connect <host>:1 -quiet' ctf@localhost

with password ctf.
```

Connecting to the server, we can find the folders with the same date of `Aug 29` as `/home/ctf`:

```shell
$ ls -al /
total 60
drwxr-xr-x   1 root root 4096 Aug 31 13:59 .
drwxr-xr-x   1 root root 4096 Aug 31 13:59 ..
lrwxrwxrwx   1 root root    7 Aug 11 00:00 bin -> usr/bin
drwxr-xr-x   2 root root 4096 May  9 14:50 boot
drwxr-xr-x   5 root root  360 Aug 31 13:59 dev
drwxr-xr-x   1 root root 4096 Aug 31 13:59 etc
drwxr-xr-x   1 root root 4096 Aug 29 16:18 home
lrwxrwxrwx   1 root root    7 Aug 11 00:00 lib -> usr/lib
lrwxrwxrwx   1 root root    9 Aug 11 00:00 lib64 -> usr/lib64
drwxr-xr-x   2 root root 4096 Aug 11 00:00 media
drwxr-xr-x   2 root root 4096 Aug 11 00:00 mnt
drwxr-xr-x   1 root root 4096 Aug 29 16:18 opt
dr-xr-xr-x 379 root root    0 Aug 31 13:59 proc
drwx------   2 root root 4096 Aug 11 00:00 root
drwxr-xr-x   1 root root 4096 Aug 31 14:05 run
lrwxrwxrwx   1 root root    8 Aug 11 00:00 sbin -> usr/sbin
drwxr-xr-x   2 root root 4096 Aug 11 00:00 srv
dr-xr-xr-x  13 root root    0 Aug 31 02:47 sys
drwxrwxrwt   2 root root 4096 Aug 11 00:00 tmp
drwxr-xr-x   1 root root 4096 Aug 11 00:00 usr
drwxr-xr-x   1 root root 4096 Aug 11 00:00 var
```

So there must be something in `/opt`:

```shell
$ find /opt
/opt
/opt/ctf
/opt/ctf/flag.blob
$ base64 /opt/ctf/flag*
KiIppwcOdIzGO5FtC1CEHFsVodUEi4nPMdpd54Kc8ZB1TLqc6r8kJRlyGr0E6YhhCkbDVA==
```

Now we get the base64 of `flag.blob`, but it is some unknown binary. Look for `blob` in the filesystem:

```shell
$ cd /usr
$ grep -R blob
grep: lib/x86_64-linux-gnu/libsystemd.so.0.35.0: binary file matches
grep: lib/x86_64-linux-gnu/libgpg-error.so.0.33.1: binary file matches
grep: lib/x86_64-linux-gnu/libgpg-error.so.0: binary file matches
grep: lib/x86_64-linux-gnu/libsystemd.so.0: binary file matches
grep: lib/x86_64-linux-gnu/libselinux.so.1: binary file matches
lib/x86_64-linux-gnu/perl-base/Config.pm:# https://github.com/Perl/perl5/blob/blead/Porting/Glossary
grep: lib/x86_64-linux-gnu/libfido2.so.1.12.0: binary file matches
grep: lib/x86_64-linux-gnu/libfido2.so.1: binary file matches
grep: lib/x86_64-linux-gnu/libcrypto.so.3: binary file matches
grep: lib/x86_64-linux-gnu/engines-3/loader_attic.so: binary file matches
grep: lib/x86_64-linux-gnu/libnss_ctf.so.2: binary file matches
grep: lib/openssh/ssh-sk-helper: binary file matches
grep: lib/openssh/ssh-keysign: binary file matches
grep: sbin/sshd: binary file matches
grep: bin/gpgv: binary file matches
grep: bin/ssh-keygen: binary file matches
grep: bin/slogin: binary file matches
grep: bin/ssh: binary file matches
grep: bin/ssh-add: binary file matches
```

The `lib/x86_64-linux-gnu/libnss_ctf.so.2` file is worth looking. Grab it locally via `base64 lib/x86_64-linux-gnu/libnss_ctf.so.2`.

Decompile via Ghidra:

```c

undefined8 _nss_ctf_getpwnam_r(char *param_1)

{
  int iVar1;
  char *__s2;
  undefined4 *in_R8;
  
  __s2 = (char *)get_trigger_user();
  iVar1 = strcmp(param_1,__s2);
  if (iVar1 == 0) {
    FUN_00101327();
  }
  *in_R8 = 2;
  return 0;
}


undefined * get_trigger_user(void)

{
  byte local_15 [9];
  uint local_c;
  
  local_15[0] = 0x11;
  local_15[1] = 0x16;
  local_15[2] = 0x11;
  local_15[3] = 0xb;
  local_15[4] = 0x1a;
  local_15[5] = 0x11;
  local_15[6] = 0x1b;
  local_15[7] = 0x10;
  local_15[8] = 0x7f;
  for (local_c = 0; local_c < 9; local_c = local_c + 1) {
    (&DAT_001040b8)[(int)local_c] = local_15[(int)local_c] ^ 0x7f;
  }
  return &DAT_001040b8;
}


void FUN_00101327(void)

{
  byte bVar1;
  char *pcVar2;
  undefined4 local_34;
  FILE *local_30;
  char *content;
  size_t local_20;
  FILE *local_18;
  long local_10;
  
  if (DAT_001040c4 == 0) {
    pcVar2 = (char *)get_blob_path();
    local_18 = fopen(pcVar2,"rb");
    if (local_18 != (FILE *)0x0) {
      fseek(local_18,0,2);
      local_20 = ftell(local_18);
      rewind(local_18);
      content = (char *)malloc(local_20 + 1);
      if (content == (char *)0x0) {
        fclose(local_18);
      }
      else {
        fread(content,1,local_20,local_18);
        fclose(local_18);
        local_34 = 0x3244ad92;
        for (local_10 = 0; local_10 < (long)local_20; local_10 = local_10 + 1) {
          bVar1 = FUN_001012ea(&local_34);
          content[local_10] = content[local_10] ^ bVar1;
        }
        content[local_20] = '\0';
        pcVar2 = (char *)get_outfile();
        local_30 = fopen(pcVar2,"w");
        if (local_30 != (FILE *)0x0) {
          fputs(content,local_30);
          fclose(local_30);
        }
        memset(content,0,local_20);
        free(content);
        DAT_001040c4 = 1;
      }
    }
  }
  return;
}


undefined * get_blob_path(void)

{
  byte local_28 [28];
  uint local_c;
  
  local_28[0] = 0x85;
  local_28[1] = 0xc5;
  local_28[2] = 0xda;
  local_28[3] = 0xde;
  local_28[4] = 0x85;
  local_28[5] = 0xc9;
  local_28[6] = 0xde;
  local_28[7] = 0xcc;
  local_28[8] = 0x85;
  local_28[9] = 0xcc;
  local_28[10] = 0xc6;
  local_28[0xb] = 0xcb;
  local_28[0xc] = 0xcd;
  local_28[0xd] = 0x84;
  local_28[0xe] = 200;
  local_28[0xf] = 0xc6;
  local_28[0x10] = 0xc5;
  local_28[0x11] = 200;
  local_28[0x12] = 0xaa;
  for (local_c = 0; local_c < 0x13; local_c = local_c + 1) {
    (&DAT_00104090)[(int)local_c] = local_28[(int)local_c] ^ 0xaa;
  }
  return &DAT_00104090;
}
```

If we implement `get_trigger_user` locally, we can see that the user name is `nintendo`:

```c
$ cat get_trigger_user.c
#include <stdint.h>
#include <stdio.h>
int main() {
  uint8_t local_15[9];
  uint8_t temp[10];
  int local_c;

  local_15[0] = 0x11;
  local_15[1] = 0x16;
  local_15[2] = 0x11;
  local_15[3] = 0xb;
  local_15[4] = 0x1a;
  local_15[5] = 0x11;
  local_15[6] = 0x1b;
  local_15[7] = 0x10;
  local_15[8] = 0x7f;
  for (local_c = 0; local_c < 9; local_c = local_c + 1) {
    temp[(int)local_c] = local_15[(int)local_c] ^ 0x7f;
  }
  temp[9] = 0;
  printf("%s\n", temp);
  return 0;
}
$ gcc get_trigger_user.c -o get_trigger_user
$ ./get_trigger_user
nintendo
```

But we cannot `su` in the remote machine. Do the same thing for `get_blob_path`:

```c
$ cat get_blob_path.c
#include <stdint.h>
#include <stdio.h>
int main() {
  uint8_t local_28[28];
  uint8_t temp[29];
  int local_c;

  local_28[0] = 0x85;
  local_28[1] = 0xc5;
  local_28[2] = 0xda;
  local_28[3] = 0xde;
  local_28[4] = 0x85;
  local_28[5] = 0xc9;
  local_28[6] = 0xde;
  local_28[7] = 0xcc;
  local_28[8] = 0x85;
  local_28[9] = 0xcc;
  local_28[10] = 0xc6;
  local_28[0xb] = 0xcb;
  local_28[0xc] = 0xcd;
  local_28[0xd] = 0x84;
  local_28[0xe] = 200;
  local_28[0xf] = 0xc6;
  local_28[0x10] = 0xc5;
  local_28[0x11] = 200;
  local_28[0x12] = 0xaa;
  for (local_c = 0; local_c < 0x13; local_c = local_c + 1) {
    temp[(int)local_c] = local_28[(int)local_c] ^ 0xaa;
  }
  temp[19] = 0;
  printf("%s\n", temp);
  return 0;
}
$ gcc get_blob_path.c -o get_blob_path
$ ./get_blob_path
/opt/ctf/flag.blob
```

So we know that the following part is for decoding the `/opt/ctf/flag.blob`, which is already known. Just repeat what the `libnss_ctf.so` does:

```c
#include <stdint.h>
#include <stdio.h>

uint32_t FUN_001012ea(uint32_t *param_1)

{
  uint32_t uVar1;

  uVar1 = *param_1 ^ *param_1 << 0xd;
  uVar1 = uVar1 ^ uVar1 >> 0x11;
  *param_1 = uVar1 ^ uVar1 << 5;
  return *param_1;
}

int main() {
  char content[100];
  FILE *fp = fopen("input", "rb");
  fread(content, 1, 52, fp);
  int local_20 = 52;
  uint32_t local_34 = 0x3244ad92;
  uint8_t bVar1;
  for (int local_10 = 0; local_10 < (long)local_20; local_10 = local_10 + 1) {
    bVar1 = FUN_001012ea(&local_34);
    content[local_10] = content[local_10] ^ bVar1;
  }
  content[local_20] = '\0';
  printf("%s\n", content);
}
```

Get flag: `corctf{nsswitch_can_be_sneaky_sometimes_i_guess_idk}`.

P.S. maybe we can just ssh to `nintendo@` and grab the flag from the output path.
