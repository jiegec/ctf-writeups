# Writeups by solution

Table of contents:

* TOC
{:toc}

## AI

- Jailbreak:
    - [System prompt leak](../2025-09-05-imaginary-ctf-2025/tax-return.md)

## Crypto

- RSA:
    - [Small n](../2018-09-28-thuctf2018/crypto/easy_rsa.md)
    - [Small e](../2025-08-16-scriptctf2025/rsa-1.md)
    - [Factorable n](../2025-08-22-brunnerctf2025/half-baked.md)
    - [Small d](../2025-09-19-k17-ctf-2025/worsehelp.md)
    - [Same m and n, different e](../2025-09-26-iran-tech-olympics-ctf-2025/techras.md)
- Discrete logarithm:
    - [Baby-step giant-step](../2025-09-08-wanqubei-quals-2025/new-trick.md)
    - [Pohlig-Hellman](../2025-09-04-nullcon-berlin-hackim-2025-ctf/field-trip.md)
- AES:
    - [Chosen plaintext attack](../2025-08-16-scriptctf2025/eaas.md)
    - [Padding oracle attack](../2025-09-04-nullcon-berlin-hackim-2025-ctf/decryption-execution-service.md)
    - [XOR attack against AES-CTR & CRC](../2025-09-04-nullcon-berlin-hackim-2025-ctf/magntic-tape.md)
- DES:
    - [Weak keys](../2018-09-28-thuctf2018/crypto/101DES.md)
    - [Slide attack](../2025-09-04-nullcon-berlin-hackim-2025-ctf/narrow-des.md)
- Double block cipher:
    - [Meet in the middle](../2025-08-16-scriptctf2025/secure-server-2.md)
- Caesar cipher:
    - [QuipQiup](../2018-09-28-thuctf2018/misc/Flow.md)
- Polynomial:
    - [Find small coefficients using LLL](../2022-11-25-hitconctf2022/babysss.md)
    - [N-th root to reduce the number of unknown coefficients](../2025-08-16-sekaictf2025/ssss.md)
    - [Find odd-degree coefficients](../2025-08-30-corctf2025/ssss.md)
- Linear congruential generator
    - [Parameter recover](../2025-09-06-cracconctf2025/ecg.md)
    - [Recover different types of LCG](./lcg.md)
- ECDSA:
    - [Reused k](../2025-09-10-watctf-f25/curve-desert.md)
- Python random number generator
    - [Solve MT19937 using known bits](./pyrand.md)

## Forensics

- Wireshark:
    - [USB keyboard events](../2018-09-28-thuctf2018/misc/Flow.md)
    - [TLS key injection](../2025-08-22-brunnerctf2025/the-secret-brunsviger.md)
    - [USB SCSI data extraction](../2025-09-04-nullcon-berlin-hackim-2025-ctf/usbstorage.md)
    - [Hostname extraction from NetBIOS](../2025-09-22-holmes-ctf-2025/the-watchmans-residue.md)
- Microsoft Word:
    - [Visual Basic](../2025-08-08-why2025/forensics/painted-black.md)
- Editor history:
    - [.viminfo replay](../2025-08-08-why2025/forensics/the-wizard.md)
- Disk image:
    - [binwalk](../2025-08-16-scriptctf2025/diskchal.md)
- Password protected files:
    - [fcrackzip](../2025-08-16-scriptctf2025/just-some-avocado.md)
    - [hashcat](../2025-08-22-brunnerctf2025/peppernuts.md)
- Audio:
    - [Spectrogram visualizer](../2025-08-16-scriptctf2025/just-some-avocado.md)
- Shell:
    - [Find files by date and time](../2025-08-30-corctf2025/nintendo-sswitch.md)
- Windows:
    - [NTUSER.DAT registry extraction using MiTeC Windows Registry Recovery](../2025-09-05-imaginary-ctf-2025/obfuscated-1.md)
    - [C:\Windows\System32\winevt\logs\*.evtx files extraction using evtx_dump](../2025-09-22-holmes-ctf-2025/the-enduring-echo.md)
    - [C:\Windows\System32\config\* registry dump using reged or hivexregedit](../2025-09-22-holmes-ctf-2025/the-enduring-echo.md)
    - [NTFS USN journal dump using USN-Journal-Parser](../2025-09-22-holmes-ctf-2025/the-watchmans-residue.md)
    - [Find recently accessed files via C:\Users\USERNAME\AppData\Roaming\Microsoft\Windows\Recent\*.lnk using lnkinfo](../2025-09-22-holmes-ctf-2025/the-watchmans-residue.md)
    - [Registry key modification time recovery via regipy](../2025-09-22-holmes-ctf-2025/the-watchmans-residue.md)
- Linux:
    - [Linux memory dump analysis using volatility3](../2025-09-22-holmes-ctf-2025/the-tunnel-without-walls.md)
- TightVNC:
    - [VNC password extraction](../2025-09-05-imaginary-ctf-2025/obfuscated-1.md)

## Misc

- Image steganography:
    - [StegSolve](../2018-09-28-thuctf2018/misc/Format.md)
- Text steganography:
    - [Zero width characters](../2025-09-19-k17-ctf-2025/discord.md)
- Audio steganography:
    - [Sonic visualizer](../2025-09-26-iran-tech-olympics-ctf-2025/rider.md)
- Representations:
    - [Minecraft](../2025-08-16-scriptctf2025/enchant.md)
    - [Zeckendorf representation](../2025-08-22-brunnerctf2025/pie-recipe.md)
    - [EBCDIC](../2025-08-22-brunnerctf2025/the-great-mainframe-bake-off.md)
- Font:
    - [Ligature](../2025-08-29-tfcctf2025/font-leagues.md)
- Side channel:
    - [Blind execution with time side channel](../2025-09-26-iran-tech-olympics-ctf-2025/koori.md)
- PDF:
    - [Decompress /FlateDecode via qpdf](../2025-09-27-sunshine-ctf-2025/pretty-delicious-food.md)

## Pwn

- Stack buffer overflow:
    - [Override return address to system](../2018-09-28-thuctf2018/pwn/pwn1.md)
    - [Return oriented programming](../2025-09-05-imaginary-ctf-2025/babybof.md)
    - [Run shellcode on stack](../2025-09-27-sunshine-ctf-2025/daytona.md)
- Format string:
    - [Blind printf arbitrary memory read](../2025-08-08-why2025/pwnable/simple-ai-bot.md)
    - [Override return address](../2025-08-22-brunnerctf2025/the-ingredient-shop.md)
    - [Random address write](../2025-09-27-sunshine-ctf-2025/jupiter.md)
- Out of bounds read/write:
    - [Arbitrary memory read](../2025-08-16-scriptctf2025/index.md)
    - [Arbitrary memory write to stdin->_IO_buf_base](https://jia.je/kb/software/glibc_file.html?h=file#stdin-_io_buf_base)
    - [FSOP](https://jia.je/kb/software/glibc_file.html?h=file#_3)
    - [FSOP via house of apple 2](../2025-09-07-blackhat-mea-ctf-quals-2025/file101.md)
    - [FSOP via house of cat](../2025-09-07-blackhat-mea-ctf-quals-2025/file101.md)
- Arbitrary file access:
    - [Access memory via /proc/self/mem](../2025-09-10-watctf-f25/hex-editor-xtended-v2.md)
- Integer overflow:
    - [Overflow to get negative integer](../2025-08-22-brunnerctf2025/online-cake-flavour-shop.md)
    - [Overflow to get zero](../2025-08-30-corctf2025/cor-shop.md)
- Ruby jail:
    - [Define new method](../2018-09-28-thuctf2018/misc/Ruby_Master_Level_1.md)
    - [Disassemble method](../2018-09-28-thuctf2018/misc/Ruby_Master_Level_2.md)
    - [Memory scan](../2018-09-28-thuctf2018/misc/Ruby_Master_Level_3.md)
    - [CVE-2018-8778: Buffer under-read in String#unpack](../2019-01-27-codegate2019/mini_converter.md)
- JavaScript jail:
    - [JSFuck, write any JavaScript using 6 characters](../2022-11-26-glacierctf2022/pwn/Break%20the%20Calculator.md)
- Python jail:
    - [Unicode bypass](../2025-08-08-why2025/misc/title-case.md)
    - [Without builtins and digits](../2025-09-12-fortid-ctf-2025/michael-scottfield.md)
    - [Access sys module from datetime.sys for Python <= 3.11](../2025-09-26-iran-tech-olympics-ctf-2025/vibe-web-mail.md)
    - [Other Python jails](./pyjail.md)
- Shell jail:
    - [Pager !/bin/sh](../2025-08-22-hitconctf2025/git-playground.md)
- Perl jail:
    - [Newline to bypass regex](../2025-09-05-imaginary-ctf-2025/pearl.md)
    - [Pipe operator to execute command and get output](../2025-09-05-imaginary-ctf-2025/pearl.md)
- Environment variable:
    - [KEY==VALUE confusion](../2025-09-12-fortid-ctf-2025/protect-the-environment.md)

## Reverse

- Fuzzing:
    - [Crash on correct input](../2021-08-15-inctf2021/find_plut0.md)
- JavaScript:
    - [Evaluate code and inspect variables in developer tools](../2025-08-08-why2025/web/why2025-ctf-times.md)
- Android:
    - [apktool](../2025-08-22-brunnerctf2025/bakedown.md)
    - [dex2jar + JD-GUI](../2025-09-05-imaginary-ctf-2025/weird-app.md)
- Memory dump:
    - [Dump memory in debugger](../2025-09-12-fortid-ctf-2025/rev-from-the-past.md)
    - [Dump arguments of library functions with ltrace](../2025-09-26-iran-tech-olympics-ctf-2025/badmode.md)
- Validation bypass:
    - [Patch conditional jump instruction](../2025-09-19-k17-ctf-2025/bait-and-switch.md)
- PyInstaller:
    - [pyinstxtractor](../2025-09-19-k17-ctf-2025/jumping.md)
- BPF:
    - [Use bpftool to dump bpf program and maps](../2025-09-27-sunshine-ctf-2025/warp.md)

## Web

- XSS:
    - [Inline JavaScript](../2018-09-28-thuctf2018/web/XSS1.md)
    - [SSRF in JavaScript](../2018-09-28-thuctf2018/web/XSS2.md)
    - [HTML injection](../2025-09-19-k17-ctf-2025/autofill.md)
    - [PDF.js vulnerability](../2025-09-19-k17-ctf-2025/pwnable-document-format.md)
- GraphQL:
    - [Schema introspection](../2022-11-26-glacierctf2022/web/FlagCoin%20Stage%201.md)
- CURL:
    - [SSRF using gopher://](../2018-09-28-thuctf2018/web/BabyWeb.md)
- PHP:
    - [php://filter for arbitrary file read](../2025-08-22-brunnerctf2025/brunsviger-huset.md)
    - [More than 1000 input variables](../2025-09-07-blackhat-mea-ctf-quals-2025/cute-csp.md)
- Flask:
    - [Jinja template injection to leak data](../2018-09-28-thuctf2018/web/Flask.md)
    - [Jinja template injection to RCE](../2025-09-27-sunshine-ctf-2025/web-forge.md)
    - [Debugger PIN leak](../2025-08-16-sekaictf2025/my-flask-app.md)
- SQL injection:
    - [Enumerate and read from unknown tables](../2018-09-28-thuctf2018/web/wdSimpleSQLv1-1.md)
    - [Arbitrary file read](../2018-09-28-thuctf2018/web/wdSimpleSQLv1-2.md)
    - [Use UNION SELECT to query extra data](../2025-09-27-sunshine-ctf-2025/lunar-shop.md)
- Json query injection:
    - [Blind recovery of hidden string](../2025-09-12-fortid-ctf-2025/jey-is-not-my-son.md)
- MongoDB:
    - [MongoDB $operator injection](../2022-11-26-glacierctf2022/web/FlagCoin%20Stage%202.md)
- Information leak:
    - [robots.txt](../2025-08-22-brunnerctf2025/brunsviger-huset.md)
- Next.js:
    - [CVE-2025-29927: Next.js Middleware Authorization Bypass](../2025-08-22-brunnerctf2025/epic-cake-battles-of-history.md)
- YAML:
    - [YAML v1.1 versus v1.2](../2025-08-30-corctf2025/yamlquiz.md)
    - [NO parsed as false](../2025-09-07-blackhat-mea-ctf-quals-2025/cute-csp.md)
- Race condition:
    - [Cookie session race condition](../2025-09-04-nullcon-berlin-hackim-2025-ctf/webby.md)
    - [Lock file race condition](../2025-09-07-blackhat-mea-ctf-quals-2025/cute-csp.md)
- Path traversal:
    - [Use / to force absolute path](../2025-09-05-imaginary-ctf-2025/codenames-1.md)
    - [Relative path](../2025-09-07-blackhat-mea-ctf-quals-2025/hash-factory.md)
- bcrypt:
    - [Length truncation to 72 bytes](../2025-09-05-imaginary-ctf-2025/passwordless.md)
- DNS:
    - [DNS rebinding attack](../2025-09-19-k17-ctf-2025/janus.md)
- Side channel:
    - [Timing side channel for password validation](../2025-09-19-k17-ctf-2025/vault.md)
