# Pie Recipe

```
Difficulty: Easy
Author: H4N5

I found this pie recipe. It is simply named "The Recipe of the Golden Phi" by baker Zeckendorf. Can you help me figure out who made it?

89|89.21|55.13.5.1|34.13.2|89.8.1|89.13.5.2|34.13.5.1|89.13.5.1|89.8.2|89.21|89.21.5|34.13.3.1|89.8|55.13|55.21.2|89.13|89.1|89.21.8.3.1|55.8.2|89.21.8.2|89.1|55.13|55.21.2|89.21.5.2|55.21.8.3.1|34.13.3.1|55.8.3|89.21.1|55.21.1|55.21.8.2|55.1|89.21.8.1|89.1|89.13.5.1|55.2|34.13.5.2|89.1|55.21.8.3|55.21.2|89.21.3.1|89.1|55.21.8.3|34.13.5.1|89.13.5|89.8.1|34.13.3.1|55.13.5.1|89.13.5.2|89.13|55.21.5|55.5.1|55.5.1
```

AI suggests that this is `Zeckendorf representation`:

```
First, the problem is titled "Pie Recipe" and it's about "The Recipe of the Golden Phi" by baker Zeckendorf. That sounds familiar. Zeckendorf is probably referring to Zeckendorf's theorem, which states that every positive integer can be uniquely represented as a sum of non-consecutive Fibonacci numbers. The "Golden Phi" might refer to the golden ratio, which is related to Fibonacci numbers.

But in the string, we have dots between numbers, like "55.13.5.1" – this might represent the sum of these Fibonacci numbers. And since they are non-consecutive? Let's see: 55, 13, 5, 1. Are these non-consecutive? Fibonacci sequence: 1,1,2,3,5,8,13,21,34,55. So 55 and 13: between them are 21 and 34, so not consecutive. 13 and 5: between them are 8, so not consecutive? 5 and 1: between them are 2 and 3, so not consecutive. So yes, this seems like Zeckendorf representation.
```

So we just sum up all the numbers in each `|x.y.z|`:

```python
text = "89|89.21|55.13.5.1|34.13.2|89.8.1|89.13.5.2|34.13.5.1|89.13.5.1|89.8.2|89.21|89.21.5|34.13.3.1|89.8|55.13|55.21.2|89.13|89.1|89.21.8.3.1|55.8.2|89.21.8.2|89.1|55.13|55.21.2|89.21.5.2|55.21.8.3.1|34.13.3.1|55.8.3|89.21.1|55.21.1|55.21.8.2|55.1|89.21.8.1|89.1|89.13.5.1|55.2|34.13.5.2|89.1|55.21.8.3|55.21.2|89.21.3.1|89.1|55.21.8.3|34.13.5.1|89.13.5|89.8.1|34.13.3.1|55.13.5.1|89.13.5.2|89.13|55.21.5|55.5.1|55.5.1"
parts = text.split("|")
for part in parts:
    num = sum([int(s) for s in part.split(".")])
    print(chr(num), end="")
```

Output: `YnJ1bm5lcns3aDNfZzAxZDNuX3BoMV8wZl96ZWNrZW5kb3JmfQ==`. It is the base64 encoding of `brunner{7h3_g01d3n_ph1_0f_zeckendorf}`.
