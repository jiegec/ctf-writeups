# cyclegolf

We need to implement a sorting algorithm using a restricted Python subset. It should sort an array as large as possible, within 1e6 cycles.

Different versions I have tried (the captialized constants need to be replaced with large numbers, see the Python script below):

Start with basic bubble sort:

Version 1, score 268:

```python
def f(m):
    # simple bubble sort
    m[I] = 1
    while m[I] > 0:
        m[I] = 0
        m[J] = 0
        while m[J] < SCORE - 1:
            if m[m[J]] > m[m[J] + 1]:
                m[TEMP] = m[m[J]]
                m[m[J]] = m[m[J] + 1]
                m[m[J] + 1] = m[TEMP]
                m[I] = 1
            m[J] = m[J] + 1
```

Version 2, score 323:

```python
def f(m):
    # simple bubble sort
    m[I] = 0

    while m[I] < SCORE:
        m[J] = 0
        while m[J] < SCORE - 1 - m[I]:
            if m[m[J]] > m[m[J] + 1]:
                m[TEMP] = m[m[J]]
                m[m[J]] = m[m[J] + 1]
                m[m[J] + 1] = m[TEMP]
            m[J] = m[J] + 1
        m[I] = m[I] + 1
```

Version 3, score 332:

```python
def f(m):
    # simple bubble sort
    m[I] = SCORE - 1
    
    while m[I] > 0:
        m[J] = 0
        while m[J] < m[I]:
            if m[m[J]] > m[m[J] + 1]:
                m[TEMP] = m[m[J]]
                m[m[J]] = m[m[J] + 1]
                m[m[J] + 1] = m[TEMP]
            m[J] = m[J] + 1
        m[I] = m[I] - 1
```

Attempt some faster sorts:

Version 4, score 571:

```python
def f(m):
    # inplace merge sort
    m[SIZE] = 1
    while m[SIZE] < SCORE:
        m[LEFT] = 0
        while m[LEFT] < SCORE:
            m[MID] = m[LEFT] + m[SIZE] - 1
            if m[MID] >= SCORE - 1:
                break

            m[RIGHT] = m[LEFT] + m[SIZE] * 2 - 1
            if m[RIGHT] >= SCORE:
                m[RIGHT] = SCORE - 1

            m[I] = m[LEFT]
            m[J] = m[MID] + 1

            while ((m[I] <= m[MID]) * (m[J] <= m[RIGHT])) > 0:
                if m[m[I]] <= m[m[J]]:
                    m[I] = m[I] + 1
                else:
                    m[TEMP] = m[m[J]]
                    m[K] = m[J]
                    while m[K] > m[I]:
                        m[m[K]] = m[m[K] - 1]
                        m[K] = m[K] - 1
                    m[m[I]] = m[TEMP]
                    m[I] = m[I] + 1
                    m[MID] = m[MID] + 1
                    m[J] = m[J] + 1

            m[LEFT] = m[LEFT] + m[SIZE] * 2
        m[SIZE] = m[SIZE] * 2
```

Version 5, score 2559:

```python
def f(m):
    # shell sort
    m[GAP] = SCORE // 2
    while m[GAP] > 0:
        m[I] = m[GAP]
        while m[I] < SCORE:
            m[TEMP] = m[m[I]]
            m[J] = m[I]

            m[K] = m[J] - m[GAP]
            while (m[K] >= 0) & (m[m[K]] > m[TEMP]):
                m[m[J]] = m[m[K]]
                m[J] = m[K]
                m[K] = m[J] - m[GAP]

            m[m[J]] = m[TEMP]
            m[I] = m[I] + 1

        m[GAP] = m[GAP] // 2
```

Version 6, score 2540:

```python
def f(m):
    # heap sort
    m[I] = 0
    while m[I] < SCORE:
        m[J] = m[I]
        while m[J] > 0:
            m[K] = (m[J] - 1) // 2
            if m[m[J]] > m[m[K]]:
                m[TEMP] = m[m[J]]
                m[m[J]] = m[m[K]]
                m[m[K]] = m[TEMP]
                m[J] = m[K]
            else:
                break
        m[I] = m[I] + 1

    m[END] = SCORE - 1
    while m[END] > 0:
        m[TEMP] = m[0]
        m[0] = m[m[END]]
        m[m[END]] = m[TEMP]

        m[J] = 0
        while 1:
            m[LEFT] = 2 * m[J] + 1
            if m[LEFT] >= m[END]:
                break

            # Find larger child
            # m[RIGHT] = m[LEFT] + 1
            m[MID] = m[LEFT] + (m[LEFT] + 1 < m[END]) * (m[m[LEFT] + 1] > m[m[LEFT]])

            if m[m[J]] < m[m[MID]]:
                m[TEMP] = m[m[J]]
                m[m[J]] = m[m[MID]]
                m[m[MID]] = m[TEMP]
                m[J] = m[MID]
            else:
                break

        m[END] = m[END] - 1
```

Based on the uniform distribution, use flash sort:

Version 7, score 11878:

```python
def f(m):
    # flash sort

    # count elements in each bucket
    m[J] = 0
    while m[J] < SCORE:
        m[BUFFER + m[m[J]] // DIST] = m[BUFFER + m[m[J]] // DIST] + 1
        m[J] = m[J] + 1

    # compute prefix sum
    m[J] = 1
    while m[J] < BUCKETS:
        m[BUFFER + m[J]] = m[BUFFER + m[J]] + m[BUFFER + m[J] - 1]
        m[J] = m[J] + 1

    # permutation
    m[I] = 0
    m[J] = 0
    m[K] = BUCKETS - 1
    while m[I] < SCORE - 1:
        while m[J] > m[BUFFER + m[K]] - 1:
            m[J] = m[J] + 1
            m[K] = m[m[J]] // DIST

        # found a non-full bucket
        m[TEMP] = m[m[J]]
        while m[J] != m[BUFFER + m[K]]:
            m[K] = m[TEMP] // DIST
            m[BUFFER + m[K]] = m[BUFFER + m[K]] - 1

            m[TEMP2] = m[m[BUFFER + m[K]]]
            m[m[BUFFER + m[K]]] = m[TEMP]
            m[TEMP] = m[TEMP2]
            m[I] = m[I] + 1

    # insertion sort step
    m[J] = 1
    while m[J] < SCORE:
        m[TEMP] = m[m[J]]
        m[I] = m[J] - 1
        while (m[I] >= 0) & (m[m[I]] > m[TEMP]):
            m[m[I] + 1] = m[m[I]]
            m[I] = m[I] - 1
        m[m[I] + 1] = m[TEMP]
        m[J] = m[J] + 1
```

Version 8, score 13534, with minor opts:

```python
def f(m):
    # flash sort

    # count elements in each bucket
    m[J] = 0
    while m[J] < SCORE:
        m[TEMP] = BUFFER + m[m[J]] // DIST
        m[m[TEMP]] = m[m[TEMP]] + 1
        m[J] = m[J] + 1

    # compute prefix sum
    m[J] = 1
    while m[J] < BUCKETS:
        m[TEMP] = BUFFER + m[J]
        m[m[TEMP]] = m[m[TEMP]] + m[m[TEMP] - 1]
        m[J] = m[J] + 1

    # permutation
    m[I] = 0
    m[J] = 0
    m[K] = BUFFER + BUCKETS - 1
    while m[I] < SCORE - 1:
        while m[J] > m[m[K]] - 1:
            m[J] = m[J] + 1
            m[K] = BUFFER + m[m[J]] // DIST

        # found a non-full bucket
        m[TEMP] = m[m[J]]
        while 1:
            m[K] = BUFFER + m[TEMP] // DIST
            m[TEMP3] = m[m[K]] - 1
            m[m[K]] = m[TEMP3]

            m[TEMP2] = m[m[TEMP3]]
            m[m[TEMP3]] = m[TEMP]
            m[TEMP] = m[TEMP2]
            m[I] = m[I] + 1
            if m[J] == m[TEMP3]:
                break

    # insertion sort step
    m[J] = 1
    while m[J] < SCORE:
        if m[m[J] - 1] <= m[m[J]]:
            # fast path
            m[J] = m[J] + 1
            continue

        m[TEMP] = m[m[J]]
        m[I] = m[J] - 1
        while m[m[I]] > m[TEMP]:
            m[m[I] + 1] = m[m[I]]
            m[I] = m[I] - 1
        m[m[I] + 1] = m[TEMP]
        m[J] = m[J] + 1
```

Test harness:

```python
from pwn import *
import json

if args.PROG:
    file = args.PROG
else:
    file = "sort.py"

left = 100
right = 15000
buckets = 4096
while left + 1 < right:
    mid = (left + right) // 2

    score = mid
    code = (
        open(file)
        .read()
        .replace("SCORE", str(score))
        .replace("BUCKETS", str(buckets))
        .replace("DIST", str((2**64) // buckets))
        .replace("SIZE", "999995")
        .replace("MID", "999993")
        .replace("RIGHT", "999992")
        .replace("END", "999990")
        .replace("I", "999999")
        .replace("J", "999998")
        .replace("TEMP3", "999988")
        .replace("TEMP2", "999989")
        .replace("TEMP", "999997")
        .replace("K", "999996")
        .replace("LEFT", "999994")
        .replace("GAP", "999991")
        .replace("BUFFER", "900000")
    )
    print(code)

    req = json.dumps(
        {
            "code": code,
            "score": score,
        }
    )

    p = process(["python3", "main.py"])
    p.sendline(req.encode())
    res = json.loads(p.recvall().decode())
    print(res, mid, left, right)
    if res["ok"]:
        left = mid
    else:
        right = mid
```
