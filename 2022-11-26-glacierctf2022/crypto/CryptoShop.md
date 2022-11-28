# Challenge

This store sells interesting things. It also uses a questionable checkout system. Can you exploit it?

nc pwn.glacierctf.com 13370

# Writeup

Initially, we have 5 euros, and we can buy some items. A refund code is given to us, and it is computed as:

```python
def calc_refund_code(price: int, d: int, n: int):
    return pow(price, d, n)
```

Additionally, the `n` is given to us:

```python
print(f"Customernumber: {user_shop_state.pub_key.n}")
```

The unknown part is `d`. Thus, we can get the numbers via buying and refunding: $1^d \bmod n, 2^d \bmod n, 3^d \bmod n, 5^d \bmod n$. To capture the flag, we need to have 1000 euros.

So, we can fake a refund code and the buy the flag. The refund code is $1000^d \bmod n$. We can compute it by:

$$
1000^d \bmod n = ((2^d \bmod n) ^ 3 \times (5^d \bmod n) ^ 3) \bmod n
$$

We use pwntools to automate the process:

```python
from pwn import *

r = remote('pwn.glacierctf.com', 13370)
#r = process(['poetry', 'run', 'python3', 'store.py'])
r.send('\n')
s = r.recvuntil('>').decode('utf-8')
for line in s.split('\n'):
    if line.startswith('Customernumber:'):
        n = int(line.split(' ')[1])
print('n:', n)

# Buy Malduino
r.send('2\n')
s = r.recvuntil('>').decode('utf-8')
r.send('Malduino\n')
s = r.recvuntil('>').decode('utf-8')
lines = s.split('\n')
for i, line in enumerate(lines):
    print(line)
    if line.startswith('Refund-Code'):
        refund_code_2 = int(lines[i+1])
        break
# Refund
r.send('3\n')
s = r.recvuntil('>').decode('utf-8')
r.send(f'{refund_code_2}\n')
s = r.recvuntil('>').decode('utf-8')
r.send('2\n')
s = r.recvuntil('>').decode('utf-8')

# Buy Bluetooth Jammer
r.send('2\n')
s = r.recvuntil('>').decode('utf-8')
r.send('Bluetooth Jammer\n')
s = r.recvuntil('>').decode('utf-8')
lines = s.split('\n')
for i, line in enumerate(lines):
    print(line)
    if line.startswith('Refund-Code'):
        refund_code_5 = int(lines[i+1])
        break
# Refund
r.send('3\n')
s = r.recvuntil('>').decode('utf-8')
r.send(f'{refund_code_5}\n')
s = r.recvuntil('>').decode('utf-8')
r.send('5\n')
s = r.recvuntil('>').decode('utf-8')

# Compute Refund Code
refund_code = (refund_code_2 ** 3 * refund_code_5 ** 3) % n

r.send('3\n')
s = r.recvuntil('>').decode('utf-8')
r.send(f'{refund_code}\n')
s = r.recvuntil('>').decode('utf-8')
r.send('1000\n')
s = r.recvuntil('>').decode('utf-8')
print(s)

# Buy CTF-Flag
r.send('2\n')
s = r.recvuntil('>').decode('utf-8')
r.send('CTF-Flag\n')
s = r.recvuntil('>').decode('utf-8')
print(s)
# => glacierctf{RsA_S1gnAtuRe_1ssu3}
```

# Conclusion

Even if we do not know the `d` of the RSA private key, we can do some computations via modular arithmetic.
