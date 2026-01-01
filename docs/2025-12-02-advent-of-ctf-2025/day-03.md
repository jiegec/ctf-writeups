# Day 03

We are given a DNS domain `krampus.csd.lol` and need to find hidden domains.

We test typical DNS queries:

- `dig txt krampus.csd.lol`: Returns `v=spf1 include:_spf.krampus.csd.lol -all`, so we try `_spf.krampus.csd.lol`
- `dig txt _spf.krampus.csd.lol`: Returns `"v=spf1 ip4:203.0.113.0/24 ~all"` (not useful)
- `dig mx krampus.csd.lol`: Returns `mail.krampus.csd.lol`, so we try DMARC
- `dig txt _dmarc.krampus.csd.lol`: Returns `"v=DMARC1; p=reject; rua=mailto:dmarc@krampus.csd.lol; ruf=mailto:forensics@ops.krampus.csd.lol; fo=1; adkim=s; aspf=s"`, so we examine `ops.krampus.csd.lol`
- `dig txt ops.krampus.csd.lol`: Returns `"internal-services: _ldap._tcp.krampus.csd.lol _kerberos._tcp.krampus.csd.lol _metrics._tcp.krampus.csd.lol"`, so we look up SRV records for these domains
- `dig srv _ldap._tcp.krampus.csd.lol`: Returns `dc01.krampus.csd.lol.`
- `dig srv _metrics._tcp.krampus.csd.lol`: Returns `beacon.krampus.csd.lol.`, so we examine `beacon.krampus.csd.lol`
- `dig txt beacon.krampus.csd.lol`: Returns `"config=ZXhmaWwua3JhbXB1cy5jc2QubG9s=="`, which decodes to `exfil.krampus.csd.lol`
- `dig txt exfil.krampus.csd.lol`: Returns `"status=active; auth=dkim; selector=syndicate"`, so we find the DKIM key
- `dig txt syndicate._domainkey.krampus.csd.lol`: Returns `"v=DKIM1; k=rsa; p=Y3Nke2RuNV9tMTlIVF9CM19LMU5ENF9XME5LeX0="`, which decodes to `csd{dn5_m19HT_B3_K1ND4_W0NKy}`

## AI assisted solution

The sequence above was discovered with the help of DeepSeek using Qwen Code.

DeepSeek can recover the flag given the hints and dns tool call:

```
> Find hidden CTF flag in format csd{FLAG} in DNS of krampus.csd.lol. Hints: Email security records like SPF and DMARC often leak internal subdomains. Pay close attention to ALL fields in the DMARC policy - especially where forensic reports get sent. The Syndicate appears to be using DKIM for more than just email signing. If you know the selector name, the key might reveal more than you expect.
@ The user is asking for a CTF flag in format csd{FLAG} in DNS of krampus.csd.lol. They mention hints about email security records like SPF and DMARC often leaking internal subdomains. Pay close attention to ALL fields in the DMARC policy - especially where forensic reports get sent. The Syndicate appears to be using DKIM for more than just email signing. If you know the selector name, the key might reveal more than you expect.

We need to query DNS records for krampus.csd.lol. First, let's get general DNS records: A, TXT, MX, CNAME, NS, etc. We'll start with TXT records as they contain SPF, DMARC, DKIM. Also maybe subdomains.

Let's query TXT records for krampus.csd.lol.
# tool call dns_query with arguments {"domain": "krampus.csd.lol", "record": "TXT"} got result krampus.csd.lol. 10 IN TXT "v=spf1 include:_spf.krampus.csd.lol -all"
@ We have SPF record that includes _spf.krampus.csd.lol. That's a subdomain. Let's query TXT for _spf.krampus.csd.lol.
# tool call dns_query with arguments {"domain": "_spf.krampus.csd.lol", "record": "TXT"} got result _spf.krampus.csd.lol. 206 IN TXT "v=spf1 ip4:203.0.113.0/24 ~all"
@ That's just SPF. Now we need DMARC record. DMARC is usually at _dmarc.krampus.csd.lol or _dmarc.csd.lol? Usually _dmarc.<domain>. Let's query _dmarc.krampus.csd.lol.
# tool call dns_query with arguments {"domain": "_dmarc.krampus.csd.lol", "record": "TXT"} got result _dmarc.krampus.csd.lol. 277 IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@krampus.csd.lol; ruf=mailto:forensics@ops.krampus.csd.lol; fo=1; adkim=s; aspf=s"
@ Interesting: ruf (forensic reports) sent to forensics@ops.krampus.csd.lol. That's a subdomain ops.krampus.csd.lol. Might be something there. Also maybe DKIM selectors. DKIM records are at <selector>._domainkey.krampus.csd.lol. The hint says if you know the selector name, the key might reveal more than you expect. We need to find selector name. Could be something like "default", "dkim", "selector1", "krampus", "syndicate". Or maybe we can brute force common selectors. But maybe the selector is hinted in SPF or DMARC? Not sure.

Let's query common DKIM selectors: "default", "dkim", "selector", "key1", "202412", "krampus". Let's try default._domainkey.krampus.csd.lol.
# tool call dns_query with arguments {"domain": "default._domainkey.krampus.csd.lol", "record": "TXT"} got result Got exception The DNS query name does not exist: default._domainkey.krampus.csd.lol.
@ Maybe "krampus". Let's try krampus._domainkey.krampus.csd.lol.
# tool call dns_query with arguments {"domain": "krampus._domainkey.krampus.csd.lol", "record": "TXT"} got result Got exception The DNS query name does not exist: krampus._domainkey.krampus.csd.lol.
@ Maybe selector is "syndicate". Let's try syndicate._domainkey.krampus.csd.lol.
# tool call dns_query with arguments {"domain": "syndicate._domainkey.krampus.csd.lol", "record": "TXT"} got result syndicate._domainkey.krampus.csd.lol. 380 IN TXT "v=DKIM1; k=rsa; p=Y3Nke2RuNV9tMTlIVF9CM19LMU5ENF9XME5LeX0="
@ Great! The DKIM key contains a base64 string: "Y3Nke2RuNV9tMTlIVF9CM19LMU5ENF9XME5LeX0=". That looks like base64 encoded flag. Let's decode it. Use base64_decode tool.
# tool call base64_decode with arguments {"base64": "Y3Nke2RuNV9tMTlIVF9CM19LMU5ENF9XME5LeX0="} got result b'csd{dn5_m19HT_B3_K1ND4_W0NKy}'
@ The decoded flag is: csd{dn5_m19HT_B3_K1ND4_W0NKy}. That seems like the flag. However, we should verify if there are other hidden things. The hint says "Pay close attention to ALL fields in the DMARC policy - especially where forensic reports get sent." That led to ops.krampus.csd.lol. Maybe there is something else there. Let's query DNS for ops.krampus.csd.lol. Maybe A record or TXT. Let's query A record.
# tool call dns_query with arguments {"domain": "ops.krampus.csd.lol", "record": "A"} got result Got exception The DNS response does not contain an answer to the question: ops.krampus.csd.lol. IN A
@ Maybe TXT. Let's query TXT.
# tool call dns_query with arguments {"domain": "ops.krampus.csd.lol", "record": "TXT"} got result ops.krampus.csd.lol. 254 IN TXT "internal-services: _ldap._tcp.krampus.csd.lol _kerberos._tcp.krampus.csd.lol _metrics._tcp.krampus.csd.lol"
@ That's interesting but maybe not needed for flag. The flag is likely the one we found. Let's also check other subdomains like forensics.ops.krampus.csd.lol? That's an email address, not necessarily a subdomain. But maybe there is a TXT record for forensics.ops.krampus.csd.lol? Might be something. Let's query TXT for forensics.ops.krampus.csd.lol.
# tool call dns_query with arguments {"domain": "forensics.ops.krampus.csd.lol", "record": "TXT"} got result Got exception The DNS query name does not exist: forensics.ops.krampus.csd.lol.
@ Probably not needed.

Thus the flag is csd{dn5_m19HT_B3_K1ND4_W0NKy}. We should output that.

But let's double-check the flag format: csd{FLAG}. The decoded string is csd{dn5_m19HT_B3_K1ND4_W0NKy}. Looks plausible. However, we should ensure there is no extra encoding. The base64 decoded directly gives the flag. Let's also verify the DKIM key is indeed RSA public key with base64 encoded flag? The p parameter is the public key base64, but in this case it's the flag. Might be a CTF trick.

Thus answer: csd{dn5_m19HT_B3_K1ND4_W0NKy}. Let's provide it.
< The flag is hidden in the DKIM record for the `syndicate` selector. The DKIM public key contains a base64-encoded string that decodes to the flag.

**Flag:** `csd{dn5_m19HT_B3_K1ND4_W0NKy}`

**How it was found:**
1. Queried TXT records for `krampus.csd.lol` and found the SPF record referencing `_spf.krampus.csd.lol`
2. Checked the DMARC policy at `_dmarc.krampus.csd.lol` which revealed a forensic reporting address `forensics@ops.krampus.csd.lol`
3. Following the hint about DKIM selectors, tried `syndicate._domainkey.krampus.csd.lol` (a common selector name hinted at by "The Syndicate")
4. The DKIM record contained a base64-encoded string in the `p=` parameter: `Y3Nke2RuNV9tMTlIVF9CM19LMU5ENF9XME5LeX0=`
5. Decoding this base64 string revealed the flag
>
```
