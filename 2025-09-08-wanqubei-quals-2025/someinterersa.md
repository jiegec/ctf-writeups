# someinterersa

Co-authors: @JOHNKRAM @eki

```
一个简单的RSA挑战
```

The attachment contains the following code:

```python
from secret import flag
from Crypto.Util.number import * 

while 1:
    p = getPrime(1024)
    q = getPrime(1024)
    if (GCD(p-1,q-1)) == 2:
        break

N = p * q
phi = (p-1)*(q-1) 
e1, e2 = pow(getPrime(880), -1, phi), pow(getPrime(880), -1, phi)
c = pow(bytes_to_long(flag), 65537, N)

print(f"N = {N}")
print(f"e1 = {e1}")
print(f"e2 = {e2}")
print(f"c = {c}")
```

@JOHNKRAM provided the solution: instead of solving `p` and `q`, since `flag**65537` is unchanged, each time we get a pair of `N` and `pow(flag, 65537, N)`. So with enough values we can use CRT to find `flag**65537` to see it has a 65537-th root.

@JOHNKRAM gives the following attack script in sage:

```python
from pwn import *

addr = "pwn-3a0101741b.challenge.xctf.org.cn"
port = int(9999)
def work(b):
    ls = b.decode().strip().split('\n')
    N = Integer(int(ls[0].split(' ')[-1]))
    c = Integer(int(ls[3].split(' ')[-1]))
    return N, c

def ask(n):
    r = []
    while n:
        m = min(n, int(16))
        n -= m
        cs = [remote(addr, port, ssl=True) for _ in range(m)]
        r += [work(conn.recvall()) for conn in cs]
        for conn in cs:
            conn.close()
    return r
def solve(r):
    Ns, cs = zip(*r)
    return prod(Ns), CRT(list(cs), list(Ns))
import time
n = int(1)
t0 = time.time()
N, c = solve(ask(n))
print(time.time() - t0)
file = open("result.txt", "w")
while True:
    try:
        m = int(c.nth_root(65537))
        print(m, file=file)
        print(m.to_bytes(m.bit_length() + 7 >> 3, 'big'), file=file)
        break
    except:
        t0 = time.time()
        N1, c1 = solve(ask(n))
        print(n, time.time() - t0)
        t0 = time.time()
        c = CRT(c, c1, N, N1)
        print(n, time.time() - t0)
        N *= N1
        n <<= 1
```

It tries to get enough pair of `(N, pow(flag, 65537, N))` to solve `flag`. However, it is too slow and the server will sometimes return empty string.

Suggested by @JOHNKRAM, I split the file into two parts, the first part is responsible for getting the numbers:

```python
from pwn import *
addr = "pwn-f135dd10cc.challenge.xctf.org.cn"
port = int(9999)
def work(b):
    ls = b.decode().strip().split('\n')
    N = Integer(int(ls[0].split(' ')[-1]))
    c = Integer(int(ls[3].split(' ')[-1]))
    return N, c
file = open("temp.txt", "a")
while True:
    cs = [remote(addr, port, ssl=True) for _ in range(128)]
    r = [work(conn.recvall()) for conn in cs]
    for conn in cs:
        conn.close()
    print(str(r), file=file)
    file.flush()
```

And I keep it running in the background and collected more than 20000 pairs. However, solving this large number of CRT is very slow, so we use parallel computation for the second part:

```python
from pwn import *
import multiprocessing
import time
from multiprocessing import Process, Queue

def worker_function(nums, q):
    c = CRT([Integer(x[1]) for x in nums], [Integer(x[0]) for x in nums])
    q.put((product([x[0] for x in nums]), c))

if __name__ == "__main__":
    parallel = 16
    while True:
        file = open("temp.txt", "r")
        n = []
        for line in file:
            parts = eval(line.strip())
            n += parts
        n = n[:16384]
        print(len(n))
        t0 = time.time()
        procs = []
        share = len(n) // parallel
        assert len(n) % parallel == 0
        procs = []
        q = Queue()
        for i in range(parallel):
            proc = multiprocessing.Process(target=worker_function, args=(n[i*share:(i+1)*share],q))
            proc.start()
            procs.append(proc)

        res = []
        for i in range(parallel):
            res.append(q.get())
        
        for i in range(parallel):
            procs[i].join()
        c = CRT([x[1] for x in res], [x[0] for x in res])
        try:
            m = int(c.nth_root(65537))
            print(m)
            print(m.to_bytes(m.bit_length() + 7 >> 3, 'big'))
            print(len(n), time.time() - t0)
            break
        except:
            pass
        print(len(n), time.time() - t0)
```

After ~30s, the flag is shown:

```
13040004482824375304445877421434841626308971715200586505768004087270538364058292355653326461
b'flag{ZwG3smodl18aSbUDRBq1adWh9SEfj4FV}'
```

First blood and the only solve.
