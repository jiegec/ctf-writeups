# el camel

```
This El-Camel guy's looking a bit weird...
nc challenge.secso.cc 7001 
```

Attachment:

```python
from secrets import randbelow
from sympy import isprime

def findGenerator():
    while True:
        h = randbelow(p)
        if pow(h, q, p) != 1:
            continue

        g = pow(h, 2, p)
        if g != 1:
            return g

def rng(key):
    r = randbelow(p)
    
    c = pow(g, r * x, p)
    c += key

    return c % p

if __name__ == "__main__":
    from secret import FLAG, p, q

    assert isprime(p) and isprime(q)

    g = findGenerator()
    x = randbelow(q)

    print(f"""The Mystical El-Camel is in town!
Beat their game to win a special prize...

{p}
{q}
""")

    m0 = int(input("How tall do you want the coin to be?> "))
    m1 = int(input("How long do you want the coin to be?> "))

    m = [m0, m1]
    score = 0
    symbols_to_index = {'H': 0, 'T': 1}

    for _ in range(50):
        i = randbelow(2)
        c = rng(m[i])
        print(c)

        print("The coin has been tossed...")
        guess = input("Heads or Tails! (H or T)> ")
        guess = symbols_to_index.get(guess.upper())

        if guess == i:
            print("That's correct!\n")
            score += 1
        else:
            print("Incorrect!\n")
    
    if score > 37:
        print("ElCamel is impressed! Here is your prize...")
        print(FLAG)
    else:
        print("Better luck next time!")
```

Ask DeepSeek to solve it:

```
To solve this CTF challenge, we need to beat the game by correctly guessing the outcome of 50 coin tosses. The game uses a cryptographic RNG function that encrypts either `m0` or `m1` ( chosen by the user) with a secret value. The goal is to choose `m0` and `m1` such that we can determine which one was used in each encryption by leveraging properties of modular arithmetic and subgroups.

### Approach
1. **Understanding the RNG Function**: The RNG function generates a value `c = (g^{r * x} + key) mod p`, where `key` is either `m0` or `m1`. The value `g` is a generator of a subgroup of order `q` modulo `p`.
2. **Key Insight**: For the correct `key`, `(c - key)^q mod p = 1` because `c - key` lies in the subgroup of order `q`. For the wrong `key`, this equality holds only with negligible probability if `m0` and `m1` are chosen such that their difference is not in the difference set of the subgroup.
3. **Choosing `m0` and `m1`**: We set `m0 = 0` and `m1 = 1`. This choice ensures that for each `c`, we can compute `(c - m0)^q mod p` and `(c - m1)^q mod p`. The one that equals `1` indicates the correct `key`.
4. **Automation**: We automate the process by connecting to the server, reading `p` and `q`, sending `m0` and `m1`, and then for each of the 50 rounds, computing the values to guess the outcome.

### Solution Code

from pwn import *

def receive_next_c(conn):
    while True:
        line = conn.recvline().decode().strip()
        if line.isdigit():
            return int(line)

def main():
    host = 'localhost'  # Replace with actual host
    port = 12345        # Replace with actual port
    conn = remote(host, port)
    
    conn.recvuntil('special prize...\n')
    p_line = conn.recvline().strip()
    q_line = conn.recvline().strip()
    p = int(p_line)
    q = int(q_line)
    
    conn.recvuntil('> ')
    conn.sendline('0')
    conn.recvuntil('> ')
    conn.sendline('1')
    
    c = receive_next_c(conn)
    
    for round in range(50):
        conn.recvuntil('(H or T)> ')
        A = pow(c, q, p)
        B = pow(c - 1, q, p)
        if A == 1:
            guess = 'H'
        elif B == 1:
            guess = 'T'
        else:
            guess = 'H'
        conn.sendline(guess)
        
        if round < 49:
            c = receive_next_c(conn)
        else:
            conn.recvuntil('prize...\n')
            flag = conn.recvline().decode().strip()
            print(flag)
            
    conn.close()

if __name__ == '__main__':
    main()

### Explanation
1. **Connection Setup**: The script connects to the server and reads the values of `p` and `q` from the initial output.
2. **Sending `m0` and `m1`**: It sends `0` for `m0` and `1` for `m1` when prompted.
3. **Processing Each Round**: For each round, it receives the encrypted value `c`, then computes `(c - m0)^q mod p` and `(c - m1)^q mod p`. If the first computation equals `1`, it guesses "Heads" (H); if the second equals `1`, it guesses "Tails" (T).
4. **Receiving Next Value**: After sending the guess, it reads the next `c` value for the subsequent round. After the final guess, it reads the flag from the server output.
5. **Efficiency**: The use of modular exponentiation ensures that computations are efficient even for large values of `p` and `q`.

This approach efficiently distinguishes between the two keys by exploiting subgroup properties, ensuring a high success rate in guessing the coin toss outcomes and retrieving the flag.
```

Modify the script a little to make it work:

```python
from pwn import *

context(log_level="debug")


def receive_next_c(conn):
    while True:
        line = conn.recvline().decode().strip()
        if line.isdigit():
            return int(line)


def main():
    host = "challenge.secso.cc"  # Replace with actual host
    port = 7001  # Replace with actual port
    conn = remote(host, port)

    conn.recvuntil(b"special prize...\n")
    conn.recvline()
    p_line = conn.recvline().strip()
    q_line = conn.recvline().strip()
    p = int(p_line)
    q = int(q_line)

    conn.recvuntil(b"> ")
    conn.sendline(b"0")
    conn.recvuntil(b"> ")
    conn.sendline(b"1")

    c = receive_next_c(conn)

    for round in range(50):
        conn.recvuntil(b"(H or T)> ")
        A = pow(c, q, p)
        B = pow(c - 1, q, p)
        if A == 1:
            guess = "H"
        elif B == 1:
            guess = "T"
        else:
            guess = "H"
        conn.sendline(guess)

        if round < 49:
            c = receive_next_c(conn)
        else:
            conn.recvuntil(b"prize...\n")
            flag = conn.recvline().decode().strip()
            print(flag)

    conn.close()


if __name__ == "__main__":
    main()
```

Flag: `K17{el_gamal_th3_cam3l_h4s_s0me_nic3_squ4r3s}`.
