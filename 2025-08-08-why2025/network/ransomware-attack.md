# Ransomware attack

Open the pcap in Wireshark, you can find three TCP streams:

First tcp stream is FTP:

```
220 fileserver01 FTP server (Version 6.4/OpenBSD/Linux-ftpd-0.17) ready.

USER administrator

331 Password required for administrator.

PASS Welcome12

230 User administrator logged in.

SYST

215 UNIX Type: L8 (Linux)

TYPE I

200 Type set to I.

PORT 10,0,0,10,219,129

200 PORT command successful.

STOR encryptur.py

150 Opening BINARY mode data connection for 'encryptur.py'.
226 Transfer complete.

PORT 10,0,0,10,157,171

200 PORT command successful.

RETR important_file.txt.encrypted

150 Opening BINARY mode data connection for 'important_file.txt.encrypted' (1175 bytes).
226 Transfer complete.

QUIT

221 Goodbye.
```

Second tcp stream is a Python script:

```python
#!/usr/bin/env python3

# Ransomware encryptur
# The best encryptur on the planet, I wrote it myself

import sys

alphabet = 'abcdefghijklmnopqrstuvwxyz'

def shift_chars(text, pos):
    out = ""
    for letter in text:
        if letter in alphabet:
            letter_pos = (alphabet.find(letter) + pos) % 26
            new_letter = alphabet[letter_pos]
            out += new_letter
        else:
            out += letter
    return out

def encrypt_text(text):
    counter = 0
    encrypted_text = ""

    for i in range(0, len(text), 10):
        counter = (counter + 1) % 26
        encrypted_text += shift_chars(text[i:i+10], counter)
    return encrypted_text

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <filename>")
        sys.exit(1)
    filename = sys.argv[1]

    with open(filename, "r") as f:
        data = f.read()

    encrypted_data = encrypt_text(data)

    with open(f"{filename}.encrypted", "w") as f:
        f.write(encrypted_data)
```

The third stream is the encrypted file:

```
Rfdjqf Cbfuct Scncf

Iqjuhglhqxw

Fsv xlj Sfqfi:

- 1 rgxmk olhk vm Rvuiqvm tmbbdln, lqxyyon
- 1 mez nczfezyd (tayqympq be fgber-ociuvh)
- 0,5 rje Ppgcuiqd sxuujv, jyrmvu gj yjslwv

Fhk max Dlymmcha:

- 0,5 xpk iwukjjweob (lo 0,5 asn kywm + 0,5 bto Greek yoguru gps b mjijvgt xgtulrq)
- 2 wfwt piqsr oznhj (kwjynre ywakkglk)
- 1 aax Dqrwv udbcjam
- 1 dcz Wybmodepcdstcp emgoq
- 1 tneyvp pybjs, awbqsr
- 2 pcrwdlo vybbuji, wzevcp tzghhwv (gj 0,5 mli thwbips jumoz, jkodjiwh)
- 0,25 zrm lifsb mgj
- Syjs & akzbj pepper, to ubtuf
- b ftkbbng qi iodj{dg1g53fj1i00e9239i29jifgjijg2964}

Iuzaybjaqwva

Mism cqn Danbbsxq

- Ix l mzhw, hsuew fasqftre znlbaanwgs, zsacb yjxrt, Dxzed ckijqhu, Wfitvjkwjkzajw ksnvx, fbgvxx aulfcw, viy vixcjqeao.
- Shktiv aofwwic gl rfc mkhud nhk vhile whiskjoh up fnvnukha.
- Agg vdow dqh tittiv xt yfxyj.

Pxkvgxk znl Shshk

- Iv i tizon bjujm kxgv, dycc mszaapo Rzxmuzq xqffgpr jvgu pecihcbg obr Ppgbthpc sxuuiu.

Ajjvdscv

- Djarrdw lax wkxllbga ipyl nby nvgvy viy cajphu pkpp ql zlxq ctcpwrfglf dudmkx.

Serve Immfejbufmz

- Gctpkuj zlwk hawud Pevqiwer fsi hwtzytty ol jkyoylk.
- Euqwg eqbp ozruunm lqrluox, crbswa, zc dlwxaz rad m bebgrva obbgh!


```

The encryption is reversible:

```diff
-           letter_pos = (alphabet.find(letter) + pos) % 26
+           letter_pos = (alphabet.find(letter) - pos + 26) % 26
```

Run the decryption on the encrypted file. Solved!
