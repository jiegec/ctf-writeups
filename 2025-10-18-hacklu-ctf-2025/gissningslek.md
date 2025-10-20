# GISSNINGSLEK

```
Casino? CS cases? Pff. Now this game is really unfair.

    Connect via nc gissningslek.solven.jetzt 1024
```

Attachment:

```bash
#!/usr/bin/env bash

echo "Låt oss spela en gissningslek!"
echo "Varning: Du får inte ändra din gissning. :("

read -r user_guess

function guess() {
  rand=$(( ( RANDOM % 10000 )  + 1337 ))
  if [[ "${1}" -eq "${rand}" ]];
  then
    echo "Rätta"
  else
    echo "Fel"
    exit 1
  fi
}

for _ in {1..1000}; do
  guess "${user_guess}"
done

/readflag
```

Solve via Claude:

```
Looking at this CTF challenge, I need to analyze what's happening:

## Challenge Analysis

The bash script:
1. Asks for a single guess (`user_guess`)
2. Runs a loop 1000 times
3. Each iteration generates a random number between 1337-11336
4. Compares your guess to the random number
5. You must guess correctly ALL 1000 times to get the flag

**The key issue**: You provide ONE guess, but it's compared against 1000 different random numbers. This seems impossible... unless there's a bash quirk to exploit!

## The Solution

The vulnerability is in the comparison: `[[ "${1}" -eq "${rand}" ]]`

The `-eq` operator performs **arithmetic evaluation** in bash. If the left side contains an expression, bash will evaluate it!

**The exploit**: Make `user_guess` equal to `rand` by providing the string `rand` itself!

When you input `rand`, here's what happens:

# In the guess function:
# ${1} becomes "rand"
# ${rand} is the random number variable

[[ "rand" -eq "${rand}" ]]
# Bash evaluates "rand" arithmetically
# It looks up the variable $rand
# So it becomes: [[ <random_value> -eq <random_value> ]]
# This is ALWAYS true!

## Solution

Simply input:

rand

This works because:
- Bash's arithmetic evaluation in `-eq` will treat `rand` as a variable reference
- It evaluates to the current value of `$rand`
- So you're comparing `$rand == $rand`, which is always true!

**Alternative solutions** (if the above doesn't work):
- `RANDOM % 10000 + 1337` - directly use the same expression
- Shell expansion tricks to force re-evaluation

Try submitting `rand` as your guess!
```

Flag: `flag{it5_y0ur_lucky_d4y_h3h3_04217a096}`.
