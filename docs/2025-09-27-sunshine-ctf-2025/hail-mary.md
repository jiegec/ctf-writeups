# Hail Mary

```
Dr. Ryland Grace is in a tough spot! He has been tasked with performing an experiment on some "taumoeba" (Amoebas collected in the Tau Ceti system). He needs to try to breed them to meet certain biological parameters to ensure their survival when they return to Earth. See if you can help guide the experiments to find the optimal genetic code needed and you will be rewarded!
nc chal.sunshinectf.games 25201 
```

The challenge requires us to write a algorithm to search for an average score of 95%:

```
Welcome to the NASA Evolutionary Biology Lab! We are running tests on genetically modified taumoeba to try to optimize their survivability rating in alien atmospheres. You have 100 generations to attempt to reach an average of 95.0% that survive. Submit populations of 100 gene samples, each 10 floats (0-1) in JSON format.
          
Example: {"samples":[[0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0]....]}
          
Good luck! The survival of Earth depends on your science!
```

Write a simple genetic programming: select the best ones, crossover until we find good enough values:

```python
from pwn import *
import json
import random

# context(log_level="debug")

p = remote("chal.sunshinectf.games", 25201)

population = [[random.random() for j in range(10)] for i in range(100)]
p.recvuntil(b"science!")
p.recvline()
p.recvline()

for round in range(100):
    p.sendline(json.dumps({"samples": population}).encode())
    recv = p.recvline().decode()
    if "sun{" in recv:
        print(recv)
        break
    res = json.loads(recv)
    print(res["average"], res["generation"])
    scores = res["scores"]
    # select the best ones
    new_pop = list(zip(population, scores))
    new_pop.sort(key=lambda pop: pop[1])
    new_pop = new_pop[-10:]
    new_pop = [pop[0] for pop in new_pop]

    # crossover
    for i in range(90):
        left = random.choice(new_pop)
        right = random.choice(new_pop)
        element = [random.choice([l, r]) for l, r in zip(left, right)]
        new_pop.append(element)
    assert len(new_pop) == 100
    population = new_pop
```

Output:

```
0.6180897206455791 1
0.8099175606619751 2
0.8875584765275083 3
0.9266315553885608 4
0.9498142652561818 5
Success! Earth has been saved! Here is your flag: sun{wh4t_4_gr34t_pr0j3ct}
```
