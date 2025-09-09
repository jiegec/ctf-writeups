# minigame

```
一个简单的微信小程序
```

The attachment is a wechat mini program. From its hex dump, we can find it contains wasm and some javascript:

```shell
$ dd if=wxe4679cbcec91e410 of=temp.wasm bs=1 skip=9593 count=29
$ nix-shell -p wabt --run "wasm2c temp.wasm" > temp.c
$ dd if=wxe4679cbcec91e410 of=temp.js bs=1 skip=11512
```

The javascript contains:

```js
r.HEAPU8.set(i, u), _(2, 1, 1607),
r.HEAPU8[u + i.length] = 0, _(2, 1, 1630),
o = r._validateString(u), _(2, 1, 1653),
r._free_wrapper(u), _(2, 1, 1672),
o ? a.showResult("✓", "校验成功", "success") : a.showResult("✗", "校验失败", "fail");
```

So it is saving some data to the heap of webassembly, and check its output. The decompiled wasm is:

```c
static const u8 data_segment_data_w2c__d0[] = {
  0xff, 0xf5, 0xf8, 0xfe, 0xe2, 0xff, 0xf8, 0xfc, 0xa9, 0xfb, 0xab, 0xae, 
  0xfa, 0xad, 0xac, 0xa8, 0xfa, 0xae, 0xab, 0xa1, 0xa1, 0xaf, 0xae, 0xf8, 
  0xac, 0xaf, 0xae, 0xfc, 0xa1, 0xfa, 0xa8, 0xfb, 0xfb, 0xad, 0xfc, 0xac, 
  0xaa, 0xe4, 
};

static void init_memories(w2c_* instance) {
  wasm_rt_allocate_memory(&instance->w2c_a, 258, 258, 0, 65536);
  LOAD_DATA(instance->w2c_a, 1024u, data_segment_data_w2c__d0, 38);
}

u32 w2c__c_0(w2c_* instance, u32 var_p0) {
  u32 var_l1 = 0, var_l2 = 0, var_l3 = 0, var_l4 = 0;
  FUNC_PROLOGUE;
  u32 var_i0, var_i1, var_i2;
  var_i0 = var_p0;
  var_l3 = var_i0;
  var_i1 = 3u;
  var_i0 &= var_i1;
  var_i0 = !(var_i0);
  if (var_i0) {goto var_B2;}
  var_i0 = 0u;
  var_i1 = var_p0;
  var_i1 = i32_load8_u_default32(&instance->w2c_a, (u64)(var_i1));
  var_i1 = !(var_i1);
  if (var_i1) {goto var_B0;}
  var_L3: 
    var_i0 = var_p0;
    var_i1 = 1u;
    var_i0 += var_i1;
    var_p0 = var_i0;
    var_i1 = 3u;
    var_i0 &= var_i1;
    var_i0 = !(var_i0);
    if (var_i0) {goto var_B2;}
    var_i0 = var_p0;
    var_i0 = i32_load8_u_default32(&instance->w2c_a, (u64)(var_i0));
    if (var_i0) {goto var_L3;}
  goto var_B1;
  var_B2:;
  var_L4: 
    var_i0 = var_p0;
    var_l1 = var_i0;
    var_i1 = 4u;
    var_i0 += var_i1;
    var_p0 = var_i0;
    var_i0 = 16843008u;
    var_i1 = var_l1;
    var_i1 = i32_load_default32(&instance->w2c_a, (u64)(var_i1));
    var_l4 = var_i1;
    var_i0 -= var_i1;
    var_i1 = var_l4;
    var_i0 |= var_i1;
    var_i1 = 2155905152u;
    var_i0 &= var_i1;
    var_i1 = 2155905152u;
    var_i0 = var_i0 == var_i1;
    if (var_i0) {goto var_L4;}
  var_L5: 
    var_i0 = var_l1;
    var_p0 = var_i0;
    var_i1 = 1u;
    var_i0 += var_i1;
    var_l1 = var_i0;
    var_i0 = var_p0;
    var_i0 = i32_load8_u_default32(&instance->w2c_a, (u64)(var_i0));
    if (var_i0) {goto var_L5;}
  var_B1:;
  var_i0 = var_p0;
  var_i1 = var_l3;
  var_i0 -= var_i1;
  var_B0:;
  var_i1 = 38u;
  var_i0 = var_i0 != var_i1;
  if (var_i0) {
    var_i0 = 0u;
    goto var_Bfunc;
  }
  var_L7: 
    var_i0 = var_l2;
    var_i0 = i32_load8_u_default32(&instance->w2c_a, (u64)(var_i0) + 1024u);
    var_i1 = var_l2;
    var_i2 = var_l3;
    var_i1 += var_i2;
    var_i1 = i32_load8_s_default32(&instance->w2c_a, (u64)(var_i1));
    var_i0 ^= var_i1;
    var_p0 = var_i0;
    var_i1 = 153u;
    var_i0 = var_i0 == var_i1;
    var_l1 = var_i0;
    var_i0 = var_p0;
    var_i1 = 153u;
    var_i0 = var_i0 != var_i1;
    if (var_i0) {goto var_B8;}
    var_i0 = var_l2;
    var_i1 = 1u;
    var_i0 += var_i1;
    var_l2 = var_i0;
    var_i1 = 38u;
    var_i0 = var_i0 != var_i1;
    if (var_i0) {goto var_L7;}
    var_B8:;
  var_i0 = var_l1;
  var_Bfunc:;
  FUNC_EPILOGUE;
  return var_i0;
}
```

The first part uses magic number of `0x1010100(16843008u)`, `0x80808080(2155905152u)`, signifies that its is an optimized `strlen` optimization. Skip over `strlen`, go over the main logic:

```c
  var_L7: 
    var_i0 = var_l2;
    var_i0 = i32_load8_u_default32(&instance->w2c_a, (u64)(var_i0) + 1024u);
    var_i1 = var_l2;
    var_i2 = var_l3;
    var_i1 += var_i2;
    var_i1 = i32_load8_s_default32(&instance->w2c_a, (u64)(var_i1));
    var_i0 ^= var_i1;
    var_p0 = var_i0;
    var_i1 = 153u;
    var_i0 = var_i0 == var_i1;
    var_l1 = var_i0;
    var_i0 = var_p0;
    var_i1 = 153u;
    var_i0 = var_i0 != var_i1;
    if (var_i0) {goto var_B8;}
    var_i0 = var_l2;
    var_i1 = 1u;
    var_i0 += var_i1;
    var_l2 = var_i0;
    var_i1 = 38u;
    var_i0 = var_i0 != var_i1;
    if (var_i0) {goto var_L7;}
```

It reads data from `&w2c_a[0]` and `&w2c_a[1024]`, checks if they xor to 153. So we just xor 153 back:

```c
#include <stdint.h>
#include <stdio.h>

static uint8_t data_segment_data_w2c__d0[] = {
    0xff, 0xf5, 0xf8, 0xfe, 0xe2, 0xff, 0xf8, 0xfc, 0xa9, 0xfb,
    0xab, 0xae, 0xfa, 0xad, 0xac, 0xa8, 0xfa, 0xae, 0xab, 0xa1,
    0xa1, 0xaf, 0xae, 0xf8, 0xac, 0xaf, 0xae, 0xfc, 0xa1, 0xfa,
    0xa8, 0xfb, 0xfb, 0xad, 0xfc, 0xac, 0xaa, 0xe4,
};

int main() {
  for (int i = 0; i < 38; i++) {
    printf("%c", data_segment_data_w2c__d0[i] ^ 153);
  }
}
```

Output:

```
flag{fae0b27c451c728867a567e8c1bb4e53}
```
