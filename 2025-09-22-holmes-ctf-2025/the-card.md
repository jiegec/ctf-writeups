# The Card

```
Holmes receives a breadcrumb from Dr. Nicole Vale - fragments from a string of cyber incidents across Cogwork-1. Each lead ends the same way: a digital calling card signed JM.
```

## Question #1

```
Analyze the provided logs and identify what is the first User-Agent used by the attacker against Nicole Vale's honeypot. (string)
```

Answer in access.log:

```
2025-05-01 08:23:12 121.36.37.224 - - [01/May/2025:08:23:12 +0000] "GET /robots.txt HTTP/1.1" 200 847 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:23:45 121.36.37.224 - - [01/May/2025:08:23:45 +0000] "GET /sitemap.xml HTTP/1.1" 200 2341 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:24:12 121.36.37.224 - - [01/May/2025:08:24:12 +0000] "GET /.well-known/security.txt HTTP/1.1" 404 162 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:24:23 121.36.37.224 - - [01/May/2025:08:24:23 +0000] "GET /admin HTTP/1.1" 404 162 "-" "Lilnunc/4A4D - SpecterEye"
```

## Question #2

```
It appears the threat actor deployed a web shell after bypassing the WAF. What is the file name? (filename.ext)
```

Answer in access.log:

```
2025-05-18 15:02:12 121.36.37.224 - - [18/May/2025:15:02:12 +0000] "GET /uploads/temp_4A4D.php?cmd=ls%20-la%20/var/www/html/uploads/ HTTP/1.1" 200 2048 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
2025-05-18 15:02:23 121.36.37.224 - - [18/May/2025:15:02:23 +0000] "GET /uploads/temp_4A4D.php?cmd=whoami HTTP/1.1" 200 256 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
2025-05-18 15:02:34 121.36.37.224 - - [18/May/2025:15:02:34 +0000] "GET /uploads/temp_4A4D.php?cmd=tar%20-czf%20/tmp/exfil_4A4D.tar.gz%20/var/www/html/config/%20/var/log/webapp/ HTTP/1.1" 200 128 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
```

## Question #3

```
The threat actor also managed to exfiltrate some data. What is the name of the database that was exfiltrated? (filename.ext)
```

Answer in access.log:

```
2025-05-18 14:58:23 121.36.37.224 - - [18/May/2025:15:58:23 +0000] "GET /uploads/database_dump_4A4D.sql HTTP/1.1" 200 52428800 "-" "4A4D RetrieveR/1.0.0"
```

## Question #4

```
During the attack, a seemingly meaningless string seems to be recurring. Which one is it? (string)
```

Answer:

```
4A4D
```

## Question #5

```
OmniYard-3 (formerly Scotland Yard) has granted you access to its CTI platform. Browse to the first IP:port address and count how many campaigns appear to be linked to the honeypot attack.
```

Answer:

1. visit the website
2. count compaigns (Bio-Breach etc.) linked to `JM`

## Question #6

```
How many tools and malware in total are linked to the previously identified campaigns? (number)
```

Answer:

1. visit the website
2. count tools (NeuroScan Pro etc.) and malwares (NeuroStorm Implant etc.) linked to `JM`

## Question #7

```
It appears that the threat actor has always used the same malware in their campaigns. What is its SHA-256 hash? (sha-256 hash)
```

Answer:

1. visit the website
2. read the metadata of the indicators:

```
[file:hashes.SHA256 = '7477c4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d17477']
[file:hashes.SHA256 = '7477c4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d17477']
[file:hashes.SHA256 = '7477c4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d17477']
...
```

## Question #8

```
Browse to the second IP:port address and use the CogWork Security Platform to look for the hash and locate the IP address to which the malware connects. (Credentials: nvale/CogworkBurning!)
```

Answer:

1. visit the website
2. login using the provided credentials
3. search for `7477c4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d17477` found in last question
4. find answer in `Network Communication` section

## Question #9

```
What is the full path of the file that the malware created to ensure its persistence on systems? (/path/filename.ext)
```

Answer:

1. continue from last question
2. click `View Details`
3. find answer in `File Operations`

## Question #10

```
Finally, browse to the third IP:port address and use the CogNet Scanner Platform to discover additional details about the TA's infrastructure. How many open ports does the server have?
```

Answer:

1. visit the website
2. search for `74.77.74.77` found in previous questions
3. count `Open Ports`

## Question #11

```
Which organization does the previously identified IP belong to? (string)
```

Answer:

1. continue from last question
2. click `Details`
3. find answer under `NETWORK INFORMATION` -> `Organization:`

## Question #12

```
One of the exposed services displays a banner containing a cryptic message. What is it? (string)
```

Answer:

1. continue from last question
2. click `SERVICES`
2. find answer under `SERVICE ANALYSIS` -> `7477/tcp`
