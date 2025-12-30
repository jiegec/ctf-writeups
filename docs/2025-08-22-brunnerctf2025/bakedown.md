# BakeDown

```
Mobile

Difficulty: Beginner
Author: KyootyBella

I just shipped the very first build of my BakeDown app. I haven't done much with it yet, but I did pack it with a few nice resources already.

Try loading it onto your phone or an emulator to try it out!

Oh and btw, did you know an APK is just a ZIP file with assembled Java code and resources like strings, fonts, and images? I heard apktool might be a good tool for decoding the contents!
```

Extract the `BakeDown.apk` using apktool:

```
apktool decode BakeDown.apk
```

Find first part of flag in `BakeDown/res/values.strings.xml`:

```
    <string name="flag_part_1">brunner{Th1s_Sh0uld_B3_Th3_</string>
```

The second part is in `BakeDown/res/drawable/cake.png`:

![](bakedown.png)

The flag is: `brunner{Th1s_Sh0uld_B3_Th3_B3g1nn1ng_0f_Y0ur_M0b1l3_3xp3r13nc3}`
