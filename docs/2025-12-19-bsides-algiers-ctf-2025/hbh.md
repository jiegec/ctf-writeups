# HBH

```
I said it all ..

author: fatima
```

Solved by AI:

# BSides Algiers 2025 - Forensics: HBH Writeup

**Challenge**: HBH (Forensics)  
**Author**: fatima  
**Files**: `chall.pcap`, `CHALLENGE.md`  
**Flag**: `shellmates{h0p_by_h0p_0pt10ns_h1d3_s3cr3ts_1n_pl41n_s1ght}`

## Challenge Description

The challenge provides a PCAP file with the cryptic hint "I said it all .." in the CHALLENGE.md file. The challenge name "HBH" is the key clue.

## Initial Analysis

### File Examination

- `chall.pcap`: 62KB, contains 720 packets
- All traffic is IPv6 (unusual, should be a clue)
- Contains SSH, HTTP, and DNS traffic (red herrings)

### Traffic Overview

- **720 total packets**, all IPv6
- **SSH**: 17 identical SSH-2.0-OpenSSH_8.2 banner packets
- **HTTP**: 30 identical GET requests to `/index.html` on `example.com`
- **DNS**: Queries for common domains
- **ICMPv6**: Ping packets (critical for solution)

## Solution Walkthrough

### Step 1: Understanding "HBH"
The challenge name "HBH" stands for **Hop-By-Hop**, referring to IPv6 Hop-by-Hop extension headers (next header = 0). This is the key insight.

### Step 2: Identifying Suspicious Packets
Using scapy to analyze the pcap:

```python
from scapy.all import *
packets = rdpcap('chall.pcap')
# Filter for IPv6 packets with Hop-by-Hop options (next header = 0)
hbh_packets = [p for p in packets if p.haslayer(IPv6) and p[IPv6].nh == 0]
print(f"Found {len(hbh_packets)} packets with Hop-by-Hop options")
```

Found 25 packets with Hop-by-Hop options, but only 10 contain the 8-byte PadN option data we need.

### Step 3: Extracting Hidden Data
The Hop-by-Hop headers contain PadN options with 8-byte data fields:

```python
for pkt in packets:
    if pkt.haslayer(IPv6):
        ipv6 = pkt[IPv6]
        if ipv6.nh == 0:  # Hop-by-Hop
            if hasattr(ipv6, 'options'):
                for opt in ipv6.options:
                    if hasattr(opt, 'optdata'):
                        data = opt.optdata
                        if data and len(data) == 8:
                            # Found hidden data!
```

### Step 4: Decryption Process

The 8-byte data chunks are encrypted:

1. **XOR each byte with 0x42** (ASCII 'B')
2. **Base64 decode** the result
3. **Result**: ASCII text fragments of the flag

```python
def decrypt_data(data):
    # XOR with 0x42
    xored = bytes(b ^ 0x42 for b in data)
    # Base64 decode
    decoded = base64.b64decode(xored).decode('utf-8')
    return decoded
```

### Step 5: Extracting All Fragments
Applying the decryption to all 10 packets gives:

```
Packet 6:  shellm
Packet 88: t10ns_
Packet 220: ght}
Packet 241: ates{h
Packet 281: 3cr3ts
Packet 452: h1d3_s
Packet 545: 0p_by_
Packet 559: h0p_0p
Packet 666: 41n_s1
Packet 714: _1n_pl
```

### Step 6: Determining Correct Order (CRITICAL)
**Initial Mistake**: Using packet capture order gives incorrect flag.

**Correct Approach**: All packets are ICMPv6 Echo Request (ping) packets. The ICMPv6 sequence numbers provide the correct ordering:

```
ICMP Seq 0:  shellm    (Packet 6)
ICMP Seq 1:  ates{h    (Packet 241)
ICMP Seq 2:  0p_by_    (Packet 545)
ICMP Seq 3:  h0p_0p    (Packet 559)
ICMP Seq 4:  t10ns_    (Packet 88)
ICMP Seq 5:  h1d3_s    (Packet 452)
ICMP Seq 6:  3cr3ts    (Packet 281)
ICMP Seq 7:  _1n_pl    (Packet 714)
ICMP Seq 8:  41n_s1    (Packet 666)
ICMP Seq 9:  ght}      (Packet 220)
```

### Step 7: Flag Reconstruction
Concatenating in ICMPv6 sequence order:

- `shellm` + `ates{h` = `shellmates{`
- Remaining parts in sequence order 2-9

**Final flag**: `shellmates{h0p_by_h0p_0pt10ns_h1d3_s3cr3ts_1n_pl41n_s1ght}`

### Step 8: Plaintext Interpretation
The leetspeak translates to:

- `h0p_by_h0p_0pt10ns` = `hop_by_hop_options`
- `h1d3_s3cr3ts` = `hide_secrets`
- `1n_pl41n_s1ght` = `in_plain_sight`

**Plaintext**: `shellmates{hop_by_hop_options_hide_secrets_in_plain_sight}`

## Technical Details

### Steganography Method

- Data hidden in IPv6 Hop-by-Hop extension headers
- Specifically in PadN option data fields
- Each packet carries 8 bytes of encrypted data

### Encryption Scheme

1. **XOR encryption** with key `0x42` (ASCII 'B')
2. **Base64 encoding** of plaintext
3. Result stored in PadN option data

### Data Fragmentation

- Flag split across 10 ICMPv6 Echo Request packets
- Each packet contains 6-character fragment (8 bytes base64 → 6 bytes decoded)
- ICMPv6 sequence numbers 0-9 provide ordering

### Red Herrings

- SSH banners (identical, repeated)
- HTTP GET requests (identical, to example.com)
- DNS queries (common domains)
- All designed to distract from the actual data channel

## Solver Script
See `solve_hbh.py` for a complete, cleaned-up solver.

## Lessons Learned

1. **Challenge names are clues**: "HBH" = Hop-By-Hop = IPv6 extension headers
2. **Check all protocol layers**: Data can be hidden in unexpected places (extension headers)
3. **Consider packet context**: ICMPv6 sequence numbers matter for ordering
4. **Simple crypto is common**: XOR + base64 is a frequent CTF pattern
5. **Red herrings are intentional**: SSH/HTTP/DNS traffic was distraction

## Tools Used

- Python with scapy
- Wireshark (for initial inspection)
- Base64 and XOR operations

## Flag
`shellmates{h0p_by_h0p_0pt10ns_h1d3_s3cr3ts_1n_pl41n_s1ght}`


Solver:

```python
#!/usr/bin/env python3
"""
BSides Algiers 2025 - Forensics HBH Challenge Solver

Solves the "HBH" challenge by extracting and decrypting data hidden in
IPv6 Hop-by-Hop extension headers.

Usage: python solve_hbh.py chall.pcap

Flag: shellmates{h0p_by_h0p_0pt10ns_h1d3_s3cr3ts_1n_pl41n_s1ght}
"""

import sys
import base64
from scapy.all import rdpcap, IPv6, ICMPv6EchoRequest
from scapy.layers.inet6 import IPv6ExtHdrHopByHop

def extract_hbh_data(pcap_file):
    """
    Extract Hop-by-Hop option data from pcap file.
    
    Returns list of tuples: (packet_index, icmp_seq, decoded_string, raw_data)
    """
    packets = rdpcap(pcap_file)
    results = []
    
    for i, pkt in enumerate(packets):
        if pkt.haslayer(IPv6):
            ipv6 = pkt[IPv6]
            
            # Check for Hop-by-Hop extension header (next header = 0)
            if ipv6.nh == 0:
                # Get Hop-by-Hop options
                if hasattr(ipv6, 'options'):
                    for opt in ipv6.options:
                        if hasattr(opt, 'optdata'):
                            optdata = opt.optdata
                            # We're looking for 8-byte data chunks
                            if optdata and len(optdata) == 8:
                                # Get ICMPv6 sequence number for ordering
                                icmp_seq = None
                                if pkt.haslayer(ICMPv6EchoRequest):
                                    icmp = pkt[ICMPv6EchoRequest]
                                    icmp_seq = icmp.seq
                                else:
                                    # Manual parsing if scapy doesn't recognize it
                                    try:
                                        # ICMPv6 Echo Request is type 128
                                        # Structure: type(1), code(1), checksum(2), id(2), seq(2)
                                        payload = bytes(ipv6.payload)
                                        if len(payload) >= 8:
                                            # Skip Hop-by-Hop header (2 bytes header + options)
                                            # For PadN with 8 bytes data: type=1, len=8, data=8
                                            # Total options = 10 bytes, header = 2 bytes
                                            # ICMPv6 starts at byte 12
                                            if len(payload) >= 12:
                                                icmp_start = payload[12:]
                                                if len(icmp_start) >= 8:
                                                    icmp_type = icmp_start[0]
                                                    if icmp_type == 128:  # Echo Request
                                                        icmp_seq = int.from_bytes(icmp_start[6:8], 'big')
                                    except:
                                        pass
                                
                                results.append((i, icmp_seq, optdata))
    
    return results

def decrypt_data(data):
    """
    Decrypt the data: XOR with 0x42, then base64 decode.
    
    Args:
        data: 8-byte encrypted data
        
    Returns:
        Decoded string (6 characters)
    """
    # XOR each byte with 0x42
    xored = bytes(b ^ 0x42 for b in data)
    
    # Base64 decode
    try:
        decoded = base64.b64decode(xored)
        return decoded.decode('utf-8')
    except Exception as e:
        return f"[DECODE_ERROR: {e}]"

def solve_challenge(pcap_file):
    """
    Main solver function.
    
    Args:
        pcap_file: Path to pcap file
        
    Returns:
        The flag as string
    """
    print(f"Solving HBH challenge from {pcap_file}")
    print("=" * 60)
    
    # Step 1: Extract data from Hop-by-Hop options
    print("\n1. Extracting data from IPv6 Hop-by-Hop options...")
    packets_data = extract_hbh_data(pcap_file)
    
    if not packets_data:
        print("ERROR: No Hop-by-Hop data found!")
        return None
    
    print(f"   Found {len(packets_data)} packets with hidden data")
    
    # Step 2: Decrypt each packet's data
    print("\n2. Decrypting data (XOR 0x42 + base64 decode)...")
    decrypted_packets = []
    
    for idx, seq, data in packets_data:
        decrypted = decrypt_data(data)
        decrypted_packets.append((idx, seq, decrypted, data))
        print(f"   Packet {idx:3d} (ICMP seq {seq if seq is not None else 'N/A'}): {decrypted}")
    
    # Step 3: Determine correct order
    print("\n3. Determining correct order...")
    
    # Check if we have ICMP sequence numbers
    has_seq_numbers = all(seq is not None for _, seq, _, _ in decrypted_packets)
    
    if has_seq_numbers:
        print("   Using ICMPv6 sequence numbers for ordering")
        # Sort by ICMP sequence number
        sorted_packets = sorted(decrypted_packets, key=lambda x: x[1])
    else:
        print("   WARNING: No ICMP sequence numbers found, using packet index order")
        print("   (This may give incorrect flag if packets are out of order)")
        sorted_packets = sorted(decrypted_packets, key=lambda x: x[0])
    
    # Step 4: Reconstruct flag
    print("\n4. Reconstructing flag...")
    
    # Extract just the decoded strings in order
    flag_parts = [decoded for _, _, decoded, _ in sorted_packets]
    print(f"   Parts in order: {flag_parts}")
    
    # Combine parts
    flag = ''.join(flag_parts)
    print(f"\n5. Final flag: {flag}")
    
    # Step 5: Provide plaintext interpretation
    print("\n6. Plaintext interpretation:")
    # Remove shellmates{ and }
    flag_body = flag[11:-1]
    
    # Simple leetspeak to plaintext conversion
    leet_map = {
        '0': 'o',
        '1': 'i',
        '3': 'e',
        '4': 'a',
        '5': 's',
        '7': 't',
        '8': 'b',
        '9': 'g',
        '@': 'a',
        '$': 's',
        '!': 'i'
    }
    
    plaintext = flag_body
    for leet, normal in leet_map.items():
        plaintext = plaintext.replace(leet, normal)
    
    # Add spaces for readability (based on underscores)
    plaintext_readable = plaintext.replace('_', ' ')
    print(f"   {plaintext_readable}")
    
    return flag

def main():
    if len(sys.argv) != 2:
        print("Usage: python solve_hbh.py <pcap_file>")
        print("Example: python solve_hbh.py chall.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    try:
        flag = solve_challenge(pcap_file)
        
        if flag:
            print("\n" + "=" * 60)
            print(f"SUCCESS! Flag: {flag}")
        else:
            print("\nFailed to solve challenge")
            sys.exit(1)
            
    except FileNotFoundError:
        print(f"ERROR: File not found: {pcap_file}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
```
