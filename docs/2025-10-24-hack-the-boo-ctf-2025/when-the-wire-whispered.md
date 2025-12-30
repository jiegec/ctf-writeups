# When The Wire Whispered

Flag 1: What is the username affected by the spray?

Inject TLS key into the capture:

```shell
editcap --inject-secrets tls,tls-lsa.log capture.pcap output.pcap
```

Open `output.pcap` in Wireshark. Filter by TLS, we find NTLMSSP_AUTH succeeded with `stoneheart_keeper52` user.

Flag 2: What is the password for that username

TODO

Flag 3: What is the website the victim is currently browsing. (TLD only: google.com)

TODO

Flag 4: What is the username:password combination for website `http://barrowick.htb`

In the `Unknown clipboard command` packets, we can find the following info from the payload:

```
WhHl$        : 1760985367592
timeLastUsed           : 1760985367592
timePasswordChanged    : 1760985367592
timesUsed              : 1
syncCounter            : 1
everSynced             : False
encryptedUnknownFields : MEMEEPgAAAAAAAAAAAAAAAAAAAEwHQYJYIZIAWUDBAEqBBAMTSKG67hjRBPvJo6dI64+BBDCI5HcBudCU9rSKU5bY6q2
username               : night_threader
password               : ThreadSight_03$Moon

id                     : 5
hostname               : http://barrowick.htb
formSubmitURL          :
usernameField          :
passwordField          :
guid                   : {23a64d8d-6327-48fd-9042-b4ef6b0acf5d}
encType                : 1
timeCreated            : 1760985367604
timeLastUsed           : 1760985367604
timePasswordChanged    : 1760985367604
timesUsed              : 1
sy

WhHl$ncCounter            : 1
everSynced             : False
encryptedUnknownFields : MEMEEPgAAAAAAAAAAAAAAAAAAAEwHQYJYIZIAWUDBAEqBBBwdJwssMn5gPitwx8QISEEBBBu/b1b3BL4X0aDv5BjRPn5
username               : candle_eyed
password               : AshWitness_99@Tomb

id                     : 6
hostname               : http://ashforge.htb
formSubmitURL          :
usernameField          :
passwordField          :
guid                   : {7a21c145-a54a-4741-a01f-e1ea0564e165}
encType                : 1
timeCreated            : 1760985367612
timeLastUsed           : 1760985367612
timePasswordChanged    : 1760985367612
timesUsed              : 1
syncCounter            : 1
everSynced             : False
encryptedUnknownFields : MEMEEPgAAAAAAAAAAAAAAAAAAAEwHQYJYIZIAWUDBAEqBBBg7Q9rquK52⏎
```
