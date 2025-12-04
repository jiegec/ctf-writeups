# Just One Line

We need to solve the Perl one-liner:

```shell
echo ${FLAG} | perl -ple '$n=()=/./g;$_=~s/./$|--?ord($&)%$n:ord($&)-$^F**5/eg'
```

The flag format is known, so we can enumerate prefixes and find the best match until we discover the entire flag:

```python
import subprocess

def count_common(left, right):
    for i in range(len(left)):
        if left[i] != right[i]:
            return i
    return len(left)

flag = "flag{00000000000000000000000000000000}"
expected = "7032652791156917671465166913651218232017181420241721222618141725201868182311"
for i in range(5, len(flag)-1):
    best_flag = ""
    best_count = 0
    for ch in ["a", "b", "c", "d", "e", "f", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]:
        new_flag = flag[:i] + ch + flag[i+1:]
        output = subprocess.check_output(f"""echo {new_flag} | perl -ple '$n=()=/./g;$_=~s/./$|--?ord($&)%$n:ord($&)-$^F**5/eg'""", shell=True, encoding="utf-8").strip()

        if count_common(output, expected) > best_count:
            best_flag = new_flag
            best_count = count_common(output, expected)
    flag = best_flag
    print(flag)
```

Solved!
