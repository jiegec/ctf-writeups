# comparing

```
by cleverbear57
Description

I put my flag into this program, but now I lost the flag. Here is the program, and the output. Could you use it to find the flag?

Attachments

comparing.cpp output.txt
```

`comparing.cpp` in attachment:

```c
#include <iostream>
#include <algorithm>
#include <vector>
#include <string>
#include <numeric>
#include <map>
#include <cmath>
#include <set>
#include <fstream>
#include <queue>
#include <unordered_map>
#include <cstring>
#include <list>
#include <cassert>
#include <tuple>
using namespace std;

class Compare {
public:
    bool operator()(tuple<char, char, int> a, tuple<char, char, int> b) {
        return static_cast<int>(get<0>(a)) + static_cast<int>(get<1>(a)) > static_cast<int>(get<0>(b)) + static_cast<int>(get<1>(b));
    }
};

string even(int val1, int val3, int ii) {
    string out = to_string(val1) + to_string(val3) + to_string(ii);
    string x = to_string(val1) + to_string(val3);
    for (int i = x.size() - 1; i >= 0; i--) {
        out += x[i];
    }
    return out;
}

string odd(int val1, int val3, int ii) {
    int out = stoi(to_string(val1) + to_string(val3) + to_string(ii));
    int i = 0;
    int addend = 0;
    while (i < 100) { addend += i; i++; }
    i--;
    while (i >= 0) { addend -= i; i--; }
    return to_string(out + addend);
}

int main()
{
    string flag = "REDACTED";
    priority_queue<tuple<char, char, int>, vector<tuple<char, char, int>>, Compare> pq;
    for (int i = 0; i < flag.size() / 2; i++) {
        tuple<char, char, int> x = { flag[i * 2],flag[i * 2 + 1],i };
        pq.push(x);
    }
    vector<string> out;
    while (!pq.empty()) {
        int val1 = static_cast<int>(get<0>(pq.top()));
        int val2 = static_cast<int>(get<1>(pq.top()));
        int i1 = get<2>(pq.top());
        pq.pop();
        int val3 = static_cast<int>(get<0>(pq.top()));
        int val4 = static_cast<int>(get<1>(pq.top()));
        int i2 = get<2>(pq.top());
        pq.pop();
        if (i1 % 2 == 0) { out.push_back(even(val1, val3, i1)); }
        else { out.push_back(odd(val1, val3, i1)); }
        if (i2 % 2 == 0) { out.push_back(even(val2, val4, i2)); }
        else { out.push_back(odd(val2, val4, i2)); }
    }
    for (int i = 0; i < out.size(); i++) {
        cout << out[i] << endl;
    }
}
```

It prints the data in two formats, `even` and `odd`. The even format prints `val1 + val3 + ii + val3_rev + val1_rev`, the odd format prints `val1 + val3 + ii`, so it is easy to figure out the parameters:

```python
data = [
    ("even", 95, 48, 12),
    ("odd", 49, 109, 5),
    ("odd", 101, 48, 13),
    ("odd", 56, 109, 7),
    ("even", 102, 116, 14),
    ("even", 57, 48, 10),
    ("odd", 117, 112, 3),
    ("even", 51, 64, 8),
    ("odd", 114, 95, 9),
    ("even", 64, 99, 6),
    ("even", 105, 116, 0),
    ("odd", 99, 102, 1),
    ("even", 123, 101, 2),
    ("odd", 99, 125, 15),
    ("odd", 114, 115, 11),
    ("even", 115, 116, 4),
]
```

Next, two adjacent entries are printed in the same loop:

```c
while (!pq.empty()) {
    int val1 = static_cast<int>(get<0>(pq.top()));
    int val2 = static_cast<int>(get<1>(pq.top()));
    int i1 = get<2>(pq.top());
    pq.pop();
    int val3 = static_cast<int>(get<0>(pq.top()));
    int val4 = static_cast<int>(get<1>(pq.top()));
    int i2 = get<2>(pq.top());
    pq.pop();
    if (i1 % 2 == 0) { out.push_back(even(val1, val3, i1)); }
    else { out.push_back(odd(val1, val3, i1)); }
    if (i2 % 2 == 0) { out.push_back(even(val2, val4, i2)); }
    else { out.push_back(odd(val2, val4, i2)); }
}
```

So we collect all values and indies from adjacent entries, and recover the flag:

```python
data = [
    ("even", 95, 48, 12),
    ("odd", 49, 109, 5),
    ("odd", 101, 48, 13),
    ("odd", 56, 109, 7),
    ("even", 102, 116, 14),
    ("even", 57, 48, 10),
    ("odd", 117, 112, 3),
    ("even", 51, 64, 8),
    ("odd", 114, 95, 9),
    ("even", 64, 99, 6),
    ("even", 105, 116, 0),
    ("odd", 99, 102, 1),
    ("even", 123, 101, 2),
    ("odd", 99, 125, 15),
    ("odd", 114, 115, 11),
    ("even", 115, 116, 4),
]

result = [0] * 32

for i in range(0, len(data), 2):
    i1 = data[i][3]
    val1 = data[i][1]
    val3 = data[i][2]
    i2 = data[i+1][3]
    val2 = data[i+1][1]
    val4 = data[i+1][2]
    result[i1 * 2] = val1
    result[i1 * 2 + 1] = val2
    result[i2 * 2] = val3
    result[i2 * 2 + 1] = val4
print(bytes(result))
```

Get flag: `ictf{cu3st0m_c0mp@r@t0rs_1e8f9e}`.
