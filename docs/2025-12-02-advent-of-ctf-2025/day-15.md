# Day 15 Image Security

Forensics Question 1:

```
We have recently intercepted a message of one of our users trying to rizz another person. The message is very old and uses a very old cipher. The message is provided bellow:
Xyebl V czkhijj klue go l qmueji'w tal? Tsmm ijy dshe yogcdg ssu qerr tpkhmjfki

What is the decrypted message?
```

TODO

Forensics Question 2:

```
What is the exact name of the startup script that gives a fake flag?
```

Answer: from process list: `jokehaha.exe` (6 pts)

Forensics Question 3:

```
We have intercepted ANOTHER message, this time though we found the executable that encrypts it as well(located on desktop). Here is the encoded string:
AEUBzgKoA6cEVAVBBtQIoQkRC9QNaw9kE8QQ0xIuFvkZMBy7GsobGRwhHnk=

What is the decoded message?
```

We found that the binary encodes each input character separately. So we can bruteforce the prefix until a match is found:

```python
#!/usr/bin/env python3
import subprocess
import string
import sys

def encrypt(input_str):
    """Run encrypt.exe with given input and return the encrypted output"""
    try:
        # Use wine to run the Windows executable
        result = subprocess.run(
            ['wine', 'encrypt.exe'],
            input=input_str.encode('utf-8'),
            capture_output=True,
            text=False
        )

        # Parse the output to get the encrypted string
        output = result.stdout.decode('utf-8', errors='ignore')
        for line in output.split('\n'):
            if line.startswith('Input your string:Encrypted:'):
                return line.split('Input your string:Encrypted:')[1].strip()

        return None
    except Exception as e:
        print(f"Error encrypting '{input_str}': {e}")
        return None

def main():
    target = "AEUBzgKoA6cEVAVBBtQIoQkRC9QNaw9kE8QQ0xIuFvkZMBy7GsobGRwhHnk="
    print(f"Target encrypted output: {target}")
    print(f"Target length in base64: {len(target)}")
    
    # Try to decode to see byte length
    import base64
    target_bytes = base64.b64decode(target)
    print(f"Target byte length: {len(target_bytes)}")
    
    # Brute force character by character
    plaintext = ""
    max_length = 100  # Reasonable max length
    
    # Try printable ASCII characters first
    charset = string.printable
    
    print("Starting brute force...")
    
    for position in range(max_length):
        found = False
        for char in charset:
            test_input = plaintext + char
            encrypted = encrypt(test_input)
            
            if encrypted:
                # Also check if encrypted is exactly the target (we're done)
                if encrypted == target:
                    plaintext += char
                    print(f"Found complete match! Plaintext: '{plaintext}'")
                    return plaintext
                # Check if this encrypted output matches the beginning of target
                if target_bytes.startswith(base64.b64decode(encrypted)):
                    plaintext += char
                    print(f"Found char at position {position}: '{char}' -> plaintext so far: '{plaintext}'")
                    found = True
                    break
        
        if not found:
            print(f"Could not find character at position {position}")
            print(f"Current plaintext: '{plaintext}'")
            break
    
    print(f"Final plaintext: '{plaintext}'")
    return plaintext

if __name__ == "__main__":
    main()
```

Result: `pyinstallermybeloveddd` (6 pts).

Application Updates:

- Upgrade 7zip to 25.01 (3 pts)
- Upgrade Notepad++ to v8.8.9 (3 pts)

Policy Violation:

- Remove non-work related files: `C:\Users\Elf2\Downloads\hexstrike-ai.zip` (3 pts)
- Uninstall Discord (2 pts)
- Uninstall Wireshark (2 pts)
- Remove malware: `C:\Users\Elf1\Downloads\*` (4 pts)
- Remove `C:\Windows\System32\en-US\jokehaha.exe` (3 pts)

User Auditing:

- Remove `Grinch` account that is not in the Authorized Users list (3 pts)
- Drop the Administrator privileged of `Kevin`: it is not in the Authorized Administrators list (3 pts)
- Change weak password of Elf3 to a secure one (3 pts)
- Assign a password for Buddy, previously no password (3 pts)

Local Policy:

- Enforce password complexity: Local Security Policy -> Account Policies -> Password Policy -> Password must meet complexity requirements -> Enabled (2 pts)
- Following the provided material, enable many sensitive auditing settings under Local Security Policy -> Advanced Audit Policy Configuration -> System Audit Policies - Local Group Policy Object, not sure which is the required one (2 pts)

Other security hardening:

- Turn on Windows Defender Firewall (3 pts)
- Enable Remote Desktop in Settings, require devices to use Network Level Authentication to connect (4 pts)
- Remove all shared folders: Computer Management -> System Tools -> Shared Folders -> Shares -> Right click each shared folder except `IPC$` -> Stop sharing (3 pts)
- Ask Microsoft Defender to scan and remove malware, enable protection (4 pts)
