# DoughBot

```
Difficulty: Beginner
Author: rvsmvs

Our state-of-the-art smart mixer, DoughBot, crashed during a routine kneading cycle. Luckily, a technician was monitoring the device over UART and captured the memory output just before the reboot.

Analyze the captured dump and see what the DoughBot was trying to say before it rebooted.
```

Attachment:

```
[BOOT] DoughBot 1.2.4
[INFO] Initializing sensor calibration...
[INFO] Sensor calibration complete.
[INFO] Establishing Wi-Fi connection...
[WARN] Wi-Fi unstable, retrying...
[INFO] Uploading diagnostics...
[DEBUG] Loading configuration from EEPROM...
[EEPROM CONFIG DUMP @ 0x2000]
    device_name     = "DoughBot"
    firmware_ver    = 1.2.4
    knead_duration  = 780
    mix_speed       = AUTO
    safety_timeout  = 300
    temp_unit       = "C"
    debug_enabled   = true
    log_mode        = FULL

// dev.note: bootlog_flag=YnJ1bm5lcnttMXgzZF9zMWduYWxzXzRfc3VyZX0=

[CRASH] Unexpected interrupt.
[REBOOT] Attempting recovery boot...
[WARN] ??>!!%0^ [RECV_ERR]  3499$
[WARN] 0x00ff @@@ERROR@:~:~
[BOOT] Safe Mode Active.
```

Decode the base64:

```shell
$ echo "YnJ1bm5lcnttMXgzZF9zMWduYWxzXzRfc3
VyZX0" | base64 -d
brunner{m1x3d_s1gnals_4_sure}
```
