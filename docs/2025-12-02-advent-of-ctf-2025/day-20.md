# Day 20 Custom Packaging

```
Our threat intel team has been tracking KRAMPUS SYNDICATE for months now. Last week, we finally caught a break. We intercepted a file transfer between two of their operatives, some kind of encrypted container using a format we've never encountered before.

One of our field agents managed to recover a partial spec from a developer workstation they compromised, but it's incomplete. Looks like the syndicate doesn't want anyone poking around their custom storage format.

The file was stored as ks2025_ops_final.kcf. Their servers follow the same pattern - ks2025-c2-01, ks2025-stage, etc. Based on chatter we've intercepted, "ks" is how they refer to themselves internally. Seems like they roll new encryption keys every January.

Here's what we know about the format:
Offset	Size	Field	Notes
0x00	4	Magic	4B 43 46 00 ("KCF\0")
0x04	2	Version	01 02 (LE) = 0x0201
0x06	2	Flags	Bit 0 indicates encryption
0x08	16	Nonce	Random bytes, likely used in key derivation
0x18	8	Timestamp	Unix timestamp, little endian
0x20	2	File count	Number of files in container
0x22	8	FAT offset	Offset to file allocation table
0x2A	4	FAT size	Size of FAT in bytes
0x2E	8	Data offset	Offset to data region
0x36	8	Data size	Size of data region
0x3E	4	Checksum	CRC32 of header bytes 0x00 to 0x3D

Header is 128 bytes. FAT entries are 96 bytes each. Data region starts at 512 byte alignment.

Our cryptanalysis team identified RC4 encryption with SHA256 key derivation. Each encrypted region uses a fresh cipher instance. The FAT appears to be encrypted with the master key directly, but individual files might use derived keys.

An intern determined the first file in the archive is a Microsoft Office document before hitting a dead end.

Per-file keys appear to incorporate the master key along with each file's position in the archive.

Figure out how this thing works and extract whatever's inside.

Hints:

Master key = SHA256(nonce || timestamp_LE || file_count_LE || identifier). The identifier is a string of six lowercase alphanumeric characters (a–z, 0–9).

Per-file key = SHA256(master_key || file_index || file_offset), truncated by a certain amount. Same endianness conventions apply.
```

Solved by AI:

# KCF Challenge - Complete Solution

## Challenge Overview
The challenge involves decrypting a custom encrypted container format called KCF (KRAMPUS SYNDICATE format). The file `ks_operations.kcf` contains 168 encrypted files with a custom header and File Allocation Table (FAT).

## Key Information from Challenge
1. **Header Structure**: 128 bytes with magic "KCF\0", version, flags, nonce, timestamp, file count, FAT offset/size, data offset/size, checksum
2. **Encryption**: RC4 with SHA256 key derivation
3. **Master Key**: `SHA256(nonce || timestamp_LE || file_count_LE || identifier)` where identifier is 6 lowercase characters
4. **Per-file Key**: `SHA256(master_key || file_index || file_offset)`, truncated by a certain amount
5. **FAT**: Encrypted with master key directly, 96 bytes per entry
6. **First file**: Microsoft Office document (as determined by an intern)

## Solution Steps

### 1. Parse Header
Extracted from `ks_operations.kcf`:

- Magic: "KCF\0"
- Version: 0x0201
- Flags: 0x1 (encrypted)
- Nonce: b371c74177fb3cdccc80a16a27738322
- Timestamp: 0x693b5b00 (1765497600)
- File count: 168
- FAT offset: 0x80
- FAT size: 0x3f00 (16128 bytes = 168 * 96)
- Data offset: 0x4000
- Data size: 0x528f30 (5416752 bytes)

### 2. Find Identifier
The identifier is 6 lowercase characters. Through analysis and testing, found to be `ks2025`.

### 3. Derive Master Key
```
master_key = SHA256(nonce || timestamp_LE || file_count_LE || "ks2025")
master_key = 95dbdd24af755276432d8b6c06f3151d7c4102a50a98f14a3b68ddb953ac9048
```

### 4. Decrypt and Parse FAT
FAT is decrypted with RC4 using master key. FAT structure analysis revealed:

- Bytes 4-7: File offset (from start of data region, uint32 LE)
- Bytes 12-15: File size (uint32 LE)
- Bytes 16-19: File size duplicate
- Bytes 20-23: Metadata/flags
- Rest: Unknown/checksum

Example for file 0:

- Offset: 0x0
- Size: 0x18800 (100352 bytes)

### 5. Per-file Key Derivation
For each file i:
```
file_key = SHA256(master_key || file_index_LE || file_offset_LE)
```
Where:

- `file_index_LE`: 4 bytes little-endian file index
- `file_offset_LE`: 8 bytes little-endian offset from FAT bytes 4-7

The key is truncated to 16 bytes (common RC4 key length).

### 6. Decrypt Files
Each file is decrypted with RC4 using its derived file key. File 0 decrypts to a Microsoft Office document (OLE format), confirming the approach is correct.

### 7. Find Flag
The flag is in file 137 (index 136). File details:

- Offset: 0x3b2470 (3875952)
- Size: 0x70c (1804 bytes)
- File key: c0fb95e3ff8a9aa83fd18c9678742459 (truncated to 16 bytes)

Decrypted content is a text document "OPERATION FROSTBITE - AFTER ACTION REVIEW" containing the flag in the authorization reference section.

## Flag
`csd{Kr4mPU5_RE4llY_l1ke5_T0_m4kE_EVeRytH1NG_CU5t0m_672Df}`

## Technical Details

### FAT Entry Structure (96 bytes)
```
Offset  Size  Description
0-3     4     Unknown (checksum/ID)
4-7     4     File offset (from data region start)
8-11    4     Unknown
12-15   4     File size
16-19   4     File size (duplicate)
20-23   4     Metadata (0x210001, 0x210002, 0x180003, etc.)
24-55   32    Unknown
56-59   4     Possibly truncation length (0x1e, 0x1b for first 2 files)
60-95   36    Unknown
```

### Key Derivation Code
```python
# Master key
key_material = nonce + struct.pack('<Q', timestamp) + struct.pack('<H', file_count) + b'ks2025'
master_key = hashlib.sha256(key_material).digest()

# Per-file key (for file i with offset from FAT)
key_material = master_key + struct.pack('<I', i) + struct.pack('<Q', offset)
full_key = hashlib.sha256(key_material).digest()
file_key = full_key[:16]  # Truncate to 16 bytes
```

### Decryption Code
```python
cipher = ARC4.new(file_key)
decrypted_data = cipher.decrypt(encrypted_file_data)
```

## Lessons Learned
1. Carefully analyze binary structures - the FAT structure was key
2. The identifier `ks2025` matches the pattern in the challenge description (ks2025_ops_final.kcf, ks2025-c2-01, etc.)
3. RC4 key truncation to 16 bytes worked, though the challenge says "truncated by a certain amount"
4. Not all files need to be examined - the flag was in file 137, not the first Office document
5. Flag format can vary (`csd{}` instead of `flag{}`)

## Tools Used

- Python with `Crypto.Cipher.ARC4` for RC4 decryption
- `hashlib` for SHA256
- `struct` for binary parsing
- Manual analysis of hex dumps and patterns

Attack script:

```python
#!/usr/bin/env python3
import struct
import hashlib
from Crypto.Cipher import ARC4
import os
import zipfile
import re

def extract_all_files():
    print("=== Extracting all KCF files ===")
    
    with open('ks_operations.kcf', 'rb') as f:
        # Parse header
        header = f.read(128)
        
        nonce = header[8:24]
        timestamp = struct.unpack('<Q', header[24:32])[0]
        file_count = struct.unpack('<H', header[32:34])[0]
        fat_offset = struct.unpack('<Q', header[34:42])[0]
        fat_size = struct.unpack('<I', header[42:46])[0]
        data_offset = struct.unpack('<Q', header[46:54])[0]
        data_size = struct.unpack('<Q', header[54:62])[0]
        
        # Read FAT and data
        f.seek(fat_offset)
        fat_data = f.read(fat_size)
        
        f.seek(data_offset)
        all_data = f.read(data_size)
    
    # Master key
    identifier = 'ks2025'
    key_material = nonce + struct.pack('<Q', timestamp) + struct.pack('<H', file_count) + identifier.encode()
    master_key = hashlib.sha256(key_material).digest()
    
    # Decrypt FAT
    cipher = ARC4.new(master_key)
    decrypted_fat = cipher.decrypt(fat_data)
    
    # Parse FAT entries
    fat_entries = []
    for i in range(file_count):
        entry = decrypted_fat[i*96:(i+1)*96]
        
        if len(entry) >= 20:
            offset = struct.unpack('<I', entry[4:8])[0] if len(entry) >= 8 else 0
            size = struct.unpack('<I', entry[12:16])[0] if len(entry) >= 16 else 0
            
            fat_entries.append({
                'index': i,
                'offset': offset,
                'size': size
            })
    
    # Extract all files with trunc_len=16 (worked for first file)
    trunc_len = 16
    output_dir = 'all_extracted_files'
    os.makedirs(output_dir, exist_ok=True)
    
    found_flag = None
    
    print(f"Extracting {len(fat_entries)} files with trunc_len={trunc_len}...")
    
    for i, entry in enumerate(fat_entries):
        if entry['size'] == 0:
            continue
        
        if entry['offset'] + entry['size'] > len(all_data):
            print(f"  File {i}: Skipping (out of bounds)")
            continue
        
        # Progress
        if i % 10 == 0:
            print(f"  Processing file {i}...")
        
        # Get encrypted data
        encrypted = all_data[entry['offset']:entry['offset']+entry['size']]
        
        # Derive file key
        key_material = master_key + struct.pack('<I', i) + struct.pack('<Q', entry['offset'])
        full_key = hashlib.sha256(key_material).digest()
        file_key = full_key[:trunc_len]
        
        # Decrypt
        try:
            cipher = ARC4.new(file_key)
            decrypted = cipher.decrypt(encrypted)
            
            # Save file
            filename = f"{output_dir}/file_{i:03d}.bin"
            with open(filename, 'wb') as f:
                f.write(decrypted)
            
            # Check for flag
            if b'csd{' in decrypted:
                print(f"\n*** File {i}: CONTAINS FLAG MARKER! ***")
                
                # Try to extract flag
                text = decrypted.decode('ascii', errors='ignore')
                flags = re.findall(r'csd\{[^}]+\}', text, re.IGNORECASE)
                if flags:
                    print(f"  Flag: {flags[0]}")
                    found_flag = flags[0]
                    break
            
            # Check for text flag
            try:
                text = decrypted.decode('utf-8', errors='ignore')
                if 'csd{' in text.lower():
                    flags = re.findall(r'csd\{[^}]+\}', text, re.IGNORECASE)
                    if flags:
                        print(f"\n*** File {i}: FLAG in text: {flags[0]} ***")
                        found_flag = flags[0]
                        break
            except:
                pass
            
            # Check file type
            if decrypted.startswith(b'PK\x03\x04'):
                print(f"  File {i}: ZIP document")
                # Save as ZIP too
                zipname = f"{output_dir}/file_{i:03d}.zip"
                with open(zipname, 'wb') as f:
                    f.write(decrypted)
                
                # Try to extract and search
                try:
                    with zipfile.ZipFile(zipname, 'r') as zf:
                        for zipfile_name in zf.namelist():
                            if 'flag' in zipfile_name.lower():
                                print(f"    ZIP contains: {zipfile_name}")
                                zf.extract(zipfile_name, output_dir)
                                
                                extracted = os.path.join(output_dir, zipfile_name)
                                try:
                                    with open(extracted, 'rb') as f:
                                        content = f.read()
                                        if b'csd{' in content:
                                            text = content.decode('ascii', errors='ignore')
                                            flags = re.findall(r'csd\{[^}]+\}', text, re.IGNORECASE)
                                            if flags:
                                                print(f"    *** FLAG in {zipfile_name}: {flags[0]} ***")
                                                found_flag = flags[0]
                                                break
                                except:
                                    pass
                except:
                    pass
            
            elif decrypted.startswith(b'\xD0\xCF\x11\xE0'):
                print(f"  File {i}: OLE/Office document")
                # Save as .doc
                docname = f"{output_dir}/file_{i:03d}.doc"
                with open(docname, 'wb') as f:
                    f.write(decrypted)
                
                # Search in OLE
                if b'csd{' in decrypted:
                    text = decrypted.decode('ascii', errors='ignore')
                    flags = re.findall(r'csd\{[^}]+\}', text, re.IGNORECASE)
                    if flags:
                        print(f"    *** FLAG in OLE: {flags[0]} ***")
                        found_flag = flags[0]
                        break
            
            # Also check for common text files
            if len(decrypted) < 10000:  # Not too large
                # Check if mostly printable
                printable = sum(32 <= b < 127 or b in [9, 10, 13] for b in decrypted)
                if printable > len(decrypted) * 0.7:  # Mostly printable
                    try:
                        text = decrypted.decode('utf-8')
                        if 'csd{' in text.lower():
                            flags = re.findall(r'csd\{[^}]+\}', text, re.IGNORECASE)
                            if flags:
                                print(f"\n*** File {i}: FLAG in text file: {flags[0]} ***")
                                found_flag = flags[0]
                                break
                    except:
                        pass
                        
        except Exception as e:
            #print(f"  File {i}: Error decrypting - {e}")
            pass
        
        if found_flag:
            break
    
    # If not found, search all extracted files
    if not found_flag:
        print("\n=== Searching all extracted files ===")
        
        for root, dirs, files in os.walk(output_dir):
            for file in files:
                filepath = os.path.join(root, file)
                
                # Skip very large files
                if os.path.getsize(filepath) > 10000000:  # 10MB
                    continue
                
                try:
                    with open(filepath, 'rb') as f:
                        content = f.read()
                    
                    # Check for flag
                    if b'flag{' in content or b'FLAG{' in content:
                        print(f"*** {file}: Contains flag marker")
                        
                        text = content.decode('ascii', errors='ignore')
                        flags = re.findall(r'flag\{[^}]+\}', text, re.IGNORECASE)
                        if flags:
                            print(f"  Flag: {flags[0]}")
                            found_flag = flags[0]
                            break
                    
                    # Check as text
                    try:
                        text = content.decode('utf-8', errors='ignore')
                        if 'flag{' in text.lower():
                            flags = re.findall(r'flag\{[^}]+\}', text, re.IGNORECASE)
                            if flags:
                                print(f"*** {file}: Flag in text: {flags[0]} ***")
                                found_flag = flags[0]
                                break
                    except:
                        pass
                        
                except Exception as e:
                    #print(f"  Error reading {file}: {e}")
                    pass
            
            if found_flag:
                break
    
    return found_flag

if __name__ == "__main__":
    flag = extract_all_files()
    
    if flag:
        print(f"\n\n*** SUCCESS! Flag: {flag} ***")
    else:
        print("\n*** No flag found in any file ***")
        print("Possible issues:")
        print("1. Wrong key derivation")
        print("2. Wrong truncation length")
        print("3. Flag is hidden/encoded in files")
        print("4. Need to look at specific file mentioned in challenge")
```
