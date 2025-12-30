# Cascader

```
Just found this super cool key exchange protocol while scrolling Hacker News between meetings ☕️⚡️🧠

It's based on some clean recurrence math — none of that dinosaur-era number theory stuff 🦕 finally, crypto that doesn't look like it was invented in the 70s 📟

It came with a working implementation too, so i plugged it right in and shipped to prod 🚀🛠️

A few people said I should’ve used something more “proven” 🔒🤷‍♂️ but honestly... this just feels right ✨

Anyway, i packaged it into a challenge. Curious to see what the skeptics say now 😏🔍
```

Attachment:

```js
"use strict";

const { createHash, createCipheriv, randomBytes } = require('node:crypto');

const KEY_SIZE_BITS = 256n;
const MAX_INT = 1n << KEY_SIZE_BITS;
const MOD = MAX_INT - 189n; // Prime number
const SEED = MAX_INT / 5n;

function linearRecurrence(seed, exponents) {
    let result = seed;
    let exp = 1n;
    while (exponents > 0n) {
        if (exponents % 2n === 1n) {
            let mult = 1n;
            for (let i = 0; i < exp; i++) {
                result = 3n * result * mult % MOD;
                mult <<= 1n;
            }
        }
        exponents >>= 1n;
        exp++;
    }
    return result;
}
// Generate a random 256 - bit BigInt
function random256BitBigInt() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    let hex = '0x';
    for (const byte of array) {
        hex += byte.toString(16).padStart(2, '0 ');
    }
    return BigInt(hex);
}
const alicePrivate = random256BitBigInt();
const bobPrivate = random256BitBigInt();
const alicePublic = linearRecurrence(SEED, alicePrivate);
const bobPublic = linearRecurrence(SEED, bobPrivate);
const aliceShared = linearRecurrence(bobPublic,
    alicePrivate);
const bobShared = linearRecurrence(alicePublic, bobPrivate);
console.log("Alice private ", alicePrivate.toString());
console.log("Bob private ", bobPrivate.toString());
console.log("Alice public ", alicePublic.toString());
console.log("Bob public ", bobPublic.toString());
console.log("Alice Shared ", aliceShared.toString());
console.log("Bob Shared ", bobShared.toString());
console.log("Alice's and Bob's shared secrets equal? ",
    aliceShared === bobShared);

function bigIntToFixedBE(n, lenBytes) {
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const buf = Buffer.from(hex, "hex");
  if (buf.length > lenBytes) {
    return buf.slice(-lenBytes);
  } else if (buf.length < lenBytes) {
    const pad = Buffer.alloc(lenBytes - buf.length, 0);
    return Buffer.concat([pad, buf]);
  }
  return buf;
}

function sha256(buf) {
  return createHash("sha256").update(buf).digest();
}

function encryptAESGCM(key, plaintext) {
   const iv = randomBytes(12);
   const cipher = createCipheriv('aes-256-gcm', key, iv);
   const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
   const tag = cipher.getAuthTag();
   return { iv, ciphertext, tag };
}

const sharedBytes = bigIntToFixedBE(aliceShared, 32);
const aesKey = sha256(sharedBytes);

const FLAG = "FortID{<REDACTED>}"

const { iv, ciphertext, tag } = encryptAESGCM(aesKey, FLAG);
console.log("ct (hex):   ", Buffer.concat([iv, ciphertext, tag]).toString("hex"));
```

```
Alice private  <REDACTED>
Bob private  <REDACTED>
Alice public  81967497404473670873986762408662347640688858544889917659709378751872081150739
Bob public  25638634989672271296647305730621408042240305773269414164982933528002524403752
Alice Shared  <REDACTED>
Bob Shared  <REDACTED>
Alice's and Bob's shared secrets equal?  true
ct (hex):    e2f84b71e84c8d696923702ddb1e35993e9108289e2d14ae8f05441ad48d1a67ead74f5f230d39dbfaae5709448c2690237ac6ab88fc26c8f362284d1e8063491d63f7c15cc3b024c62b5069605b73dd2c54fdcb2823c0c235b20e52dc5630c5f3
```

It uses the algorithm from [paper Cascader: A Recurrence-Based Key Exchange Protocol](https://eprint.iacr.org/2025/1304), but an attack is given in [paper Note: Shared Key Recovery Attack on Cascader Key Exchange Protocol](https://eprint.iacr.org/2025/1418):

![](cascader.png)

So we can find the key using public values from Alice and Bob:

```js
const { createHash, createDecipheriv } = require('node:crypto');

const KEY_SIZE_BITS = 256n;
const MAX_INT = 1n << KEY_SIZE_BITS;
const MOD = MAX_INT - 189n; // Prime number
const SEED = MAX_INT / 5n;

alicePublic = BigInt("81967497404473670873986762408662347640688858544889917659709378751872081150739");
bobPublic = BigInt("25638634989672271296647305730621408042240305773269414164982933528002524403752");

function modInv(a, b) {
    return 1n < a ? b - modInv(b % a, a) * b / a : 1n;
}

aliceShared = bobPublic * modInv(SEED, MOD) * alicePublic % MOD;

function bigIntToFixedBE(n, lenBytes) {
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const buf = Buffer.from(hex, "hex");
  if (buf.length > lenBytes) {
    return buf.slice(-lenBytes);
  } else if (buf.length < lenBytes) {
    const pad = Buffer.alloc(lenBytes - buf.length, 0);
    return Buffer.concat([pad, buf]);
  }
  return buf;
}

function sha256(buf) {
  return createHash("sha256").update(buf).digest();
}

sharedBytes = bigIntToFixedBE(aliceShared, 32);
aesKey = sha256(sharedBytes);

ct = Buffer.from("e2f84b71e84c8d696923702ddb1e35993e9108289e2d14ae8f05441ad48d1a67ead74f5f230d39dbfaae5709448c2690237ac6ab88fc26c8f362284d1e8063491d63f7c15cc3b024c62b5069605b73dd2c54fdcb2823c0c235b20e52dc5630c5f3", "hex");
iv = ct.subarray(0, 12);

cipher = createDecipheriv('aes-256-gcm', aesKey, iv);
cipher.setAuthTag(ct.subarray(ct.length - 16, ct.length));
plain = Buffer.concat([cipher.update(ct.subarray(12, ct.length - 16)), cipher.final()]);
console.log(plain.toString('utf-8'));
```

Flag: `FortID{St0p_B31n6_4_H1ps73r_4nd_5t1ck_70_Th3_G00d_0ld_D1ff1e_H3l1man}`.
