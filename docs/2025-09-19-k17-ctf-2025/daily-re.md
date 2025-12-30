# daily re

```
It's too easy to cheat at Wordle, so I fixed that! What are the words for the 72nd, 73rd, and 74th day?

Enter your answer in the format K17{<72nd day word>, <73rd day word>, <74th day word>}. For example if you think the words are 'trace', 'crane', and 'rocks' respectively, enter K17{trace, crane, rocks}.
daily-re.k17.secso.cc 
```

Read the HTML code:

```javascript
let extracted_word = Module.ccall(
    'get_word',
    'string',
    ['number', 'string'],
    [DAY_NUMBER - 1, DAY_KEY]
)
// "zonal"
```

It reads the answer word from the wasm. However, if you change DAY_NUMBER to other values, it simply returns zero. So the key was wrong.

We download the wasm file, and find something in its data field:

```
\01\00\00\008482423c95bf2f4a165f0c08ad27a800\00might\00\00 ...
```

Every 44 bytes has the same structure: index, key and word. We can extract all these words using wasm2c and a custom c program:

```c
#include <stdio.h>
static const char data_segment_data_w2c_words_d0[] = {
    0x01, 0x00, 0x00, 0x00, 0x38, 0x34, 0x38, 0x32, 0x34, 0x32, 0x33, 0x63,
    0x39, 0x35, 0x62, 0x66, 0x32, 0x66, 0x34, 0x61, 0x31, 0x36, 0x35, 0x66,
    0x30, 0x63, 0x30, 0x38, 0x61, 0x64, 0x32, 0x37, 0x61, 0x38, 0x30, 0x30,
    0x00, 0x6d, 0x69, 0x67, 0x68, 0x74, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    // ...
};

int main() {
  for (int i = 0; i * 44 + 37 < sizeof(data_segment_data_w2c_words_d0); i++) {
    printf("%d: %s\n", i, data_segment_data_w2c_words_d0 + 37 + i * 44);
  }
  return 0;
}
```

Result:

```
16: zonal
// ...
71: limbo
72: urban
73: fiber
```

Flag: `K17{limbo, urban, fiber}`.
