# curve-desert

```
Written by virchau13

Dare I suspect myself of seeing it? The oasis of random entropy, just over the horizon?
nc challs.watctf.org 3788 
```

Attachment:

```python
#!/usr/local/bin/python
import ecdsa, random, os
from Crypto.Util.number import bytes_to_long
curve = ecdsa.curves.BRAINPOOLP512r1
gen = curve.generator
n = curve.order

priv = random.randint(1, n-1)
pub = priv * gen
k = random.randint(1, n-1)


challenge = os.urandom(32)
print('Challenge hex:', challenge.hex())

def sign(msg):
    if msg == challenge:
        print('Try harder than that!')
        exit(1)
    z = bytes_to_long(msg)
    rpoint = k*gen
    r = rpoint.x() % n
    assert r != 0
    s = (pow(k, -1, n) * (z + r*priv)) % n
    return (int(r), int(s))

def verify(msg, r, s):
    z = bytes_to_long(msg)
    u1 = (pow(s, -1, n) * z) % n
    u2 = (pow(s, -1, n) * r) % n
    rpoint = u1*gen + u2*pub
    return rpoint.x() % n == r

assert verify(b'hello', *sign(b'hello'))

def menu():
    print('Menu options:')
    print('[1] Sign')
    print('[2] Verify')
    choice = int(input('Choose an option: ').strip())
    if choice == 1:
        msghex = input('Input hex of message to sign: ').strip()
        r, s = sign(bytes.fromhex(msghex))
        print(f'Your signature is: {r} {s}')
    elif choice == 2:
        msghex = input('Input hex of message to verify: ').strip()
        line = input('Input the two integers of the signature seperated by a space: ').strip()
        r, s = [int(x) for x in line.split(' ')]
        msg = bytes.fromhex(msghex)
        if verify(msg, r, s):
            print('Message verified successfully!')
            if msg == challenge:
                print('You have passed the challenge! Your reward:')
                print(open('flag.txt', 'r').read())
        else:
            print('Invalid signature.')

while True:
    menu()
```

The problem is: `k` is shared between signatures.

Ask DeepSeek to solve it:

```
To solve this CTF challenge, we need to obtain a valid signature for the challenge message without directly signing it. The signing algorithm uses ECDSA on the brainpoolP512r1 curve with a fixed nonce `k` for all signatures. This allows us to recover `k` by signing two different messages and then compute the signature for the challenge message.

### Approach
1. **Retrieve the Challenge**: The challenge is a random 32-byte value printed at the start of the program.
2. **Sign Two Messages**: Choose two distinct messages (e.g., "hello" and "world") and obtain their signatures using the sign option. Since `k` is fixed, the `r` value will be the same for both signatures.
3. **Compute the Nonce `k`**: Using the signatures and the integer values of the messages, compute `k` with the formula `k = (z1 - z2) * inv(s1 - s2, n) mod n`, where `z1` and `z2` are the integer representations of the messages, and `s1` and `s2` are the signature components.
4. **Compute Signature for Challenge**: Using the computed `k` and one of the signatures, derive the signature for the challenge message with the formula `s_challenge = s1 + inv(k, n) * (z_challenge - z1) mod n`.
5. **Verify the Challenge Signature**: Use the verify option to submit the challenge message and the computed signature `(r, s_challenge)`. If correct, the flag will be printed.

### Solution Code

from pwn import *
from Crypto.Util.number import bytes_to_long
import ecdsa

def main():
    # Connect to the server
    io = process(['python', 'server.py'])  # Replace with remote connection if needed
    # io = remote('host', port)
    
    # Receive the challenge hex
    line = io.recvline().decode().strip()
    assert line.startswith('Challenge hex: ')
    challenge_hex = line.split(': ')[1]
    challenge = bytes.fromhex(challenge_hex)
    z_challenge = bytes_to_long(challenge)
    
    # Choose two messages
    m1 = b"hello"
    m2 = b"world"
    z1 = bytes_to_long(m1)
    z2 = bytes_to_long(m2)
    
    # Get signature for m1
    io.recvuntil('Choose an option: ')
    io.sendline('1')
    io.recvuntil('Input hex of message to sign: ')
    io.sendline(m1.hex())
    io.recvuntil('Your signature is: ')
    line = io.recvline().decode().strip()
    r1, s1 = map(int, line.split())
    
    # Get signature for m2
    io.recvuntil('Choose an option: ')
    io.sendline('1')
    io.recvuntil('Input hex of message to sign: ')
    io.sendline(m2.hex())
    io.recvuntil('Your signature is: ')
    line = io.recvline().decode().strip()
    r2, s2 = map(int, line.split())
    
    # Verify that r values are the same
    if r1 != r2:
        print("Error: r values differ")
        exit(1)
    r = r1
    
    # Get curve order n
    curve = ecdsa.curves.BRAINPOOLP512r1
    n = curve.order
    
    # Compute k
    delta_z = (z1 - z2) % n
    delta_s = (s1 - s2) % n
    if delta_s == 0:
        print("Error: s1 and s2 are identical")
        exit(1)
    inv_delta_s = pow(delta_s, -1, n)
    k = (delta_z * inv_delta_s) % n
    
    # Compute signature for challenge
    kinv = pow(k, -1, n)
    s_challenge = (s1 + kinv * (z_challenge - z1)) % n
    
    # Verify the challenge signature
    io.recvuntil('Choose an option: ')
    io.sendline('2')
    io.recvuntil('Input hex of message to verify: ')
    io.sendline(challenge_hex)
    io.recvuntil('Input the two integers of the signature separated by a space: ')
    io.sendline(f'{r} {s_challenge}')
    
    # Receive the flag
    io.interactive()

if __name__ == '__main__':
    main()

### Explanation
1. **Connection Setup**: The script connects to the server running the provided code either locally or remotely.
2. **Challenge Retrieval**: The challenge value is read from the initial server output.
3. **Message Signing**: The script signs two messages ("hello" and "world") to obtain their signatures `(r, s1)` and `(r, s2)`.
4. **Nonce Calculation**: The nonce `k` is calculated using the differences in the message integers and signature components modulo the curve order `n`.
5. **Challenge Signature**: The signature for the challenge message is computed using the derived `k` and one of the signatures.
6. **Verification**: The challenge message and its computed signature are submitted for verification. Upon successful verification, the server prints the flag.

This approach exploits the fixed nonce vulnerability in ECDSA to recover the private key material and forge a signature for the challenge message.
```

Made small modifications to make it work:

```python
from pwn import *
from Cryptodome.Util.number import bytes_to_long
import ecdsa

context(log_level="debug")


def main():
    # Connect to the server
    # io = process(
    #     ["python3", "curve-desert.py"]
    # )  # Replace with remote connection if needed
    io = remote('challs.watctf.org', 3788)

    # Receive the challenge hex
    line = io.recvline().decode().strip()
    assert line.startswith("Challenge hex: ")
    challenge_hex = line.split(": ")[1]
    challenge = bytes.fromhex(challenge_hex)
    z_challenge = bytes_to_long(challenge)

    # Choose two messages
    m1 = b"hello"
    m2 = b"world"
    z1 = bytes_to_long(m1)
    z2 = bytes_to_long(m2)

    # Get signature for m1
    io.recvuntil("Choose an option: ")
    io.sendline("1")
    io.recvuntil("Input hex of message to sign: ")
    io.sendline(m1.hex())
    io.recvuntil("Your signature is: ")
    line = io.recvline().decode().strip()
    r1, s1 = map(int, line.split())

    # Get signature for m2
    io.recvuntil("Choose an option: ")
    io.sendline("1")
    io.recvuntil("Input hex of message to sign: ")
    io.sendline(m2.hex())
    io.recvuntil("Your signature is: ")
    line = io.recvline().decode().strip()
    r2, s2 = map(int, line.split())

    # Verify that r values are the same
    if r1 != r2:
        print("Error: r values differ")
        exit(1)
    r = r1

    # Get curve order n
    curve = ecdsa.curves.BRAINPOOLP512r1
    n = curve.order

    # Compute k
    delta_z = (z1 - z2) % n
    delta_s = (s1 - s2) % n
    if delta_s == 0:
        print("Error: s1 and s2 are identical")
        exit(1)
    inv_delta_s = pow(delta_s, -1, n)
    k = (delta_z * inv_delta_s) % n

    # Compute signature for challenge
    kinv = pow(k, -1, n)
    s_challenge = (s1 + kinv * (z_challenge - z1)) % n

    # Verify the challenge signature
    io.recvuntil("Choose an option: ")
    io.sendline("2")
    io.recvuntil("Input hex of message to verify: ")
    io.sendline(challenge_hex)
    io.recvuntil("Input the two integers of the signature seperated by a space: ")
    io.sendline(f"{r} {s_challenge}")

    # Receive the flag
    io.interactive()


if __name__ == "__main__":
    main()
```

Get flag: `watctf{yeah_dont_share_the_k_parameter_it_doesnt_work_out}`.
