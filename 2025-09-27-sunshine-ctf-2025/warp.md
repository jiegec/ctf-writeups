# Warp

```
The warp tunnel is letting people past our firewall!

File link: warp
```

Run `warp` with sudo, use bpftool to dump info:

```shell
# https://docs.cilium.io/en/latest/reference-guides/bpf/debug_and_test.html
$ sudo bpftool prog
988: xdp  name xdp_prog  tag xxxxxxxxxxxxxxxx
        loaded_at xxxxxxxxxxxxxxxxxxxxxxxx  uid 0
        xlated 3264B  jited 1922B  memlock 4096B  map_ids 158,159
        btf_id 293
$ sudo bpftool prog dump xlated id 988
int xdp_prog(struct xdp_md * ctx):
; void *data_end = (void *)(long)ctx->data_end;
   0: (79) r7 = *(u64 *)(r1 +8)
; void *data = (void *)(long)ctx->data;
   1: (79) r1 = *(u64 *)(r1 +0)
; if (data + sizeof(struct ethhdr) > data_end)
   2: (bf) r6 = r1
   3: (07) r6 += 14
; if (data + sizeof(struct ethhdr) > data_end)
   4: (2d) if r6 > r7 goto pc+401
   5: (bf) r2 = r1
   6: (07) r2 += 34
; if (h_proto != 0x0800)
   7: (2d) if r2 > r7 goto pc+398
   8: (69) r2 = *(u16 *)(r1 +12)
   9: (55) if r2 != 0x8 goto pc+396
; u32 ip_header_len = ip->ihl * 4;
  10: (71) r2 = *(u8 *)(r6 +0)
; u32 ip_header_len = ip->ihl * 4;
  11: (67) r2 <<= 2
  12: (57) r2 &= 60
  13: (b7) r3 = 20
; if (ip_header_len < sizeof(struct iphdr))
  14: (2d) if r3 > r2 goto pc+391
; if (ip->protocol == IPPROTO_UDP) {
  15: (71) r1 = *(u8 *)(r1 +23)
; if (ip->protocol == IPPROTO_UDP) {
  16: (15) if r1 == 0x6 goto pc+4
  17: (55) if r1 != 0x11 goto pc+388
; struct udphdr *udp = (void *)ip + ip_header_len;
  18: (0f) r6 += r2
; payload = (void *)(udp + 1);
  19: (07) r6 += 8
; } else if (ip->protocol == IPPROTO_TCP) {
  20: (05) goto pc+10
; struct tcphdr *tcp = (void *)ip + ip_header_len;
  21: (0f) r6 += r2
; if ((void *)(tcp + 1) > data_end)
  22: (bf) r1 = r6
  23: (07) r1 += 20
; if ((void *)(tcp + 1) > data_end)
  24: (2d) if r1 > r7 goto pc+381
; __u32 tcp_hdr_len = tcp->doff * 4;
  25: (69) r1 = *(u16 *)(r6 +12)
; __u32 tcp_hdr_len = tcp->doff * 4;
  26: (77) r1 >>= 2
  27: (57) r1 &= 60
; if (tcp_hdr_len < sizeof(struct tcphdr))
  28: (0f) r6 += r1
  29: (b7) r2 = 20
  30: (2d) if r2 > r1 goto pc+375
; if (payload + prefix_size > data_end)
  31: (bf) r8 = r6
  32: (07) r8 += 4
; if (payload + prefix_size > data_end)
  33: (2d) if r8 > r7 goto pc+372
; if (__builtin_memcmp(payload, prefix, prefix_size) != 0)
  34: (71) r1 = *(u8 *)(r6 +1)
  35: (67) r1 <<= 8
  36: (71) r2 = *(u8 *)(r6 +0)
  37: (4f) r1 |= r2
  38: (71) r2 = *(u8 *)(r6 +2)
  39: (67) r2 <<= 16
  40: (71) r3 = *(u8 *)(r6 +3)
  41: (67) r3 <<= 24
  42: (4f) r3 |= r2
  43: (4f) r3 |= r1
; if (__builtin_memcmp(payload, prefix, prefix_size) != 0)
  44: (55) if r3 != 0x70723457 goto pc+361
; struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  45: (18) r1 = map[id:149]
  47: (b7) r2 = 33
  48: (b7) r3 = 0
  49: (85) call bpf_ringbuf_reserve#309632
; if (!e)
  50: (15) if r0 == 0x0 goto pc+355
; if (event_data + i >= data_end)
  51: (3d) if r8 >= r7 goto pc+156
; e->text[i] = ((char *)event_data)[i];
  52: (71) r1 = *(u8 *)(r6 +4)
; e->text[i] = ((char *)event_data)[i];
  53: (73) *(u8 *)(r0 +0) = r1
; if (event_data + i >= data_end)
  54: (bf) r1 = r6
  55: (07) r1 += 5
; if (event_data + i >= data_end)
  56: (3d) if r1 >= r7 goto pc+151
; e->text[i] = ((char *)event_data)[i];
  57: (71) r1 = *(u8 *)(r6 +5)
; e->text[i] = ((char *)event_data)[i];
  58: (73) *(u8 *)(r0 +1) = r1
; if (event_data + i >= data_end)
  59: (bf) r1 = r6
  60: (07) r1 += 6
; if (event_data + i >= data_end)
  61: (3d) if r1 >= r7 goto pc+146
; e->text[i] = ((char *)event_data)[i];
  62: (71) r1 = *(u8 *)(r6 +6)
; e->text[i] = ((char *)event_data)[i];
  63: (73) *(u8 *)(r0 +2) = r1
; if (event_data + i >= data_end)
  64: (bf) r1 = r6
  65: (07) r1 += 7
; if (event_data + i >= data_end)
  66: (3d) if r1 >= r7 goto pc+141
; e->text[i] = ((char *)event_data)[i];
  67: (71) r1 = *(u8 *)(r6 +7)
; e->text[i] = ((char *)event_data)[i];
  68: (73) *(u8 *)(r0 +3) = r1
; if (event_data + i >= data_end)
  69: (bf) r1 = r6
  70: (07) r1 += 8
; if (event_data + i >= data_end)
  71: (3d) if r1 >= r7 goto pc+136
; e->text[i] = ((char *)event_data)[i];
  72: (71) r1 = *(u8 *)(r6 +8)
; e->text[i] = ((char *)event_data)[i];
  73: (73) *(u8 *)(r0 +4) = r1
; if (event_data + i >= data_end)
  74: (bf) r1 = r6
  75: (07) r1 += 9
; if (event_data + i >= data_end)
  76: (3d) if r1 >= r7 goto pc+131
; e->text[i] = ((char *)event_data)[i];
  77: (71) r1 = *(u8 *)(r6 +9)
; e->text[i] = ((char *)event_data)[i];
  78: (73) *(u8 *)(r0 +5) = r1
; if (event_data + i >= data_end)
  79: (bf) r1 = r6
  80: (07) r1 += 10
; if (event_data + i >= data_end)
  81: (3d) if r1 >= r7 goto pc+126
; e->text[i] = ((char *)event_data)[i];
  82: (71) r1 = *(u8 *)(r6 +10)
; e->text[i] = ((char *)event_data)[i];
  83: (73) *(u8 *)(r0 +6) = r1
; if (event_data + i >= data_end)
  84: (bf) r1 = r6
  85: (07) r1 += 11
; if (event_data + i >= data_end)
  86: (3d) if r1 >= r7 goto pc+121
; e->text[i] = ((char *)event_data)[i];
  87: (71) r1 = *(u8 *)(r6 +11)
; e->text[i] = ((char *)event_data)[i];
  88: (73) *(u8 *)(r0 +7) = r1
; if (event_data + i >= data_end)
  89: (bf) r1 = r6
  90: (07) r1 += 12
; if (event_data + i >= data_end)
  91: (3d) if r1 >= r7 goto pc+116
; e->text[i] = ((char *)event_data)[i];
  92: (71) r1 = *(u8 *)(r6 +12)
; e->text[i] = ((char *)event_data)[i];
  93: (73) *(u8 *)(r0 +8) = r1
; if (event_data + i >= data_end)
  94: (bf) r1 = r6
  95: (07) r1 += 13
; if (event_data + i >= data_end)
  96: (3d) if r1 >= r7 goto pc+111
; e->text[i] = ((char *)event_data)[i];
  97: (71) r1 = *(u8 *)(r6 +13)
; e->text[i] = ((char *)event_data)[i];
  98: (73) *(u8 *)(r0 +9) = r1
; if (event_data + i >= data_end)
  99: (bf) r1 = r6
 100: (07) r1 += 14
; if (event_data + i >= data_end)
 101: (3d) if r1 >= r7 goto pc+106
; e->text[i] = ((char *)event_data)[i];
 102: (71) r1 = *(u8 *)(r6 +14)
; e->text[i] = ((char *)event_data)[i];
 103: (73) *(u8 *)(r0 +10) = r1
; if (event_data + i >= data_end)
 104: (bf) r1 = r6
 105: (07) r1 += 15
; if (event_data + i >= data_end)
 106: (3d) if r1 >= r7 goto pc+101
; e->text[i] = ((char *)event_data)[i];
 107: (71) r1 = *(u8 *)(r6 +15)
; e->text[i] = ((char *)event_data)[i];
 108: (73) *(u8 *)(r0 +11) = r1
; if (event_data + i >= data_end)
 109: (bf) r1 = r6
 110: (07) r1 += 16
; if (event_data + i >= data_end)
 111: (3d) if r1 >= r7 goto pc+96
; e->text[i] = ((char *)event_data)[i];
 112: (71) r1 = *(u8 *)(r6 +16)
; e->text[i] = ((char *)event_data)[i];
 113: (73) *(u8 *)(r0 +12) = r1
; if (event_data + i >= data_end)
 114: (bf) r1 = r6
 115: (07) r1 += 17
; if (event_data + i >= data_end)
 116: (3d) if r1 >= r7 goto pc+91
; e->text[i] = ((char *)event_data)[i];
 117: (71) r1 = *(u8 *)(r6 +17)
; e->text[i] = ((char *)event_data)[i];
 118: (73) *(u8 *)(r0 +13) = r1
; if (event_data + i >= data_end)
 119: (bf) r1 = r6
 120: (07) r1 += 18
; if (event_data + i >= data_end)
 121: (3d) if r1 >= r7 goto pc+86
; e->text[i] = ((char *)event_data)[i];
 122: (71) r1 = *(u8 *)(r6 +18)
; e->text[i] = ((char *)event_data)[i];
 123: (73) *(u8 *)(r0 +14) = r1
; if (event_data + i >= data_end)
 124: (bf) r1 = r6
 125: (07) r1 += 19
; if (event_data + i >= data_end)
 126: (3d) if r1 >= r7 goto pc+81
; e->text[i] = ((char *)event_data)[i];
 127: (71) r1 = *(u8 *)(r6 +19)
; e->text[i] = ((char *)event_data)[i];
 128: (73) *(u8 *)(r0 +15) = r1
; if (event_data + i >= data_end)
 129: (bf) r1 = r6
 130: (07) r1 += 20
; if (event_data + i >= data_end)
 131: (3d) if r1 >= r7 goto pc+76
; e->text[i] = ((char *)event_data)[i];
 132: (71) r1 = *(u8 *)(r6 +20)
; e->text[i] = ((char *)event_data)[i];
 133: (73) *(u8 *)(r0 +16) = r1
; if (event_data + i >= data_end)
 134: (bf) r1 = r6
 135: (07) r1 += 21
; if (event_data + i >= data_end)
 136: (3d) if r1 >= r7 goto pc+71
; e->text[i] = ((char *)event_data)[i];
 137: (71) r1 = *(u8 *)(r6 +21)
; e->text[i] = ((char *)event_data)[i];
 138: (73) *(u8 *)(r0 +17) = r1
; if (event_data + i >= data_end)
 139: (bf) r1 = r6
 140: (07) r1 += 22
; if (event_data + i >= data_end)
 141: (3d) if r1 >= r7 goto pc+66
; e->text[i] = ((char *)event_data)[i];
 142: (71) r1 = *(u8 *)(r6 +22)
; e->text[i] = ((char *)event_data)[i];
 143: (73) *(u8 *)(r0 +18) = r1
; if (event_data + i >= data_end)
 144: (bf) r1 = r6
 145: (07) r1 += 23
; if (event_data + i >= data_end)
 146: (3d) if r1 >= r7 goto pc+61
; e->text[i] = ((char *)event_data)[i];
 147: (71) r1 = *(u8 *)(r6 +23)
; e->text[i] = ((char *)event_data)[i];
 148: (73) *(u8 *)(r0 +19) = r1
; if (event_data + i >= data_end)
 149: (bf) r1 = r6
 150: (07) r1 += 24
; if (event_data + i >= data_end)
 151: (3d) if r1 >= r7 goto pc+56
; e->text[i] = ((char *)event_data)[i];
 152: (71) r1 = *(u8 *)(r6 +24)
; e->text[i] = ((char *)event_data)[i];
 153: (73) *(u8 *)(r0 +20) = r1
; if (event_data + i >= data_end)
 154: (bf) r1 = r6
 155: (07) r1 += 25
; if (event_data + i >= data_end)
 156: (3d) if r1 >= r7 goto pc+51
; e->text[i] = ((char *)event_data)[i];
 157: (71) r1 = *(u8 *)(r6 +25)
; e->text[i] = ((char *)event_data)[i];
 158: (73) *(u8 *)(r0 +21) = r1
; if (event_data + i >= data_end)
 159: (bf) r1 = r6
 160: (07) r1 += 26
; if (event_data + i >= data_end)
 161: (3d) if r1 >= r7 goto pc+46
; e->text[i] = ((char *)event_data)[i];
 162: (71) r1 = *(u8 *)(r6 +26)
; e->text[i] = ((char *)event_data)[i];
 163: (73) *(u8 *)(r0 +22) = r1
; if (event_data + i >= data_end)
 164: (bf) r1 = r6
 165: (07) r1 += 27
; if (event_data + i >= data_end)
 166: (3d) if r1 >= r7 goto pc+41
; e->text[i] = ((char *)event_data)[i];
 167: (71) r1 = *(u8 *)(r6 +27)
; e->text[i] = ((char *)event_data)[i];
 168: (73) *(u8 *)(r0 +23) = r1
; if (event_data + i >= data_end)
 169: (bf) r1 = r6
 170: (07) r1 += 28
; if (event_data + i >= data_end)
 171: (3d) if r1 >= r7 goto pc+36
; e->text[i] = ((char *)event_data)[i];
 172: (71) r1 = *(u8 *)(r6 +28)
; e->text[i] = ((char *)event_data)[i];
 173: (73) *(u8 *)(r0 +24) = r1
; if (event_data + i >= data_end)
 174: (bf) r1 = r6
 175: (07) r1 += 29
; if (event_data + i >= data_end)
 176: (3d) if r1 >= r7 goto pc+31
; e->text[i] = ((char *)event_data)[i];
 177: (71) r1 = *(u8 *)(r6 +29)
; e->text[i] = ((char *)event_data)[i];
 178: (73) *(u8 *)(r0 +25) = r1
; if (event_data + i >= data_end)
 179: (bf) r1 = r6
 180: (07) r1 += 30
; if (event_data + i >= data_end)
 181: (3d) if r1 >= r7 goto pc+26
; e->text[i] = ((char *)event_data)[i];
 182: (71) r1 = *(u8 *)(r6 +30)
; e->text[i] = ((char *)event_data)[i];
 183: (73) *(u8 *)(r0 +26) = r1
; if (event_data + i >= data_end)
 184: (bf) r1 = r6
 185: (07) r1 += 31
; if (event_data + i >= data_end)
 186: (3d) if r1 >= r7 goto pc+21
; e->text[i] = ((char *)event_data)[i];
 187: (71) r1 = *(u8 *)(r6 +31)
; e->text[i] = ((char *)event_data)[i];
 188: (73) *(u8 *)(r0 +27) = r1
; if (event_data + i >= data_end)
 189: (bf) r1 = r6
 190: (07) r1 += 32
; if (event_data + i >= data_end)
 191: (3d) if r1 >= r7 goto pc+16
; e->text[i] = ((char *)event_data)[i];
 192: (71) r1 = *(u8 *)(r6 +32)
; e->text[i] = ((char *)event_data)[i];
 193: (73) *(u8 *)(r0 +28) = r1
; if (event_data + i >= data_end)
 194: (bf) r1 = r6
 195: (07) r1 += 33
; if (event_data + i >= data_end)
 196: (3d) if r1 >= r7 goto pc+11
; e->text[i] = ((char *)event_data)[i];
 197: (71) r1 = *(u8 *)(r6 +33)
; e->text[i] = ((char *)event_data)[i];
 198: (73) *(u8 *)(r0 +29) = r1
; if (event_data + i >= data_end)
 199: (bf) r1 = r6
 200: (07) r1 += 34
; if (event_data + i >= data_end)
 201: (3d) if r1 >= r7 goto pc+6
; e->text[i] = ((char *)event_data)[i];
 202: (71) r1 = *(u8 *)(r6 +34)
; e->text[i] = ((char *)event_data)[i];
 203: (73) *(u8 *)(r0 +30) = r1
; if (event_data + i >= data_end)
 204: (07) r6 += 35
; if (event_data + i >= data_end)
 205: (3d) if r6 >= r7 goto pc+2
; e->text[i] = ((char *)event_data)[i];
 206: (71) r1 = *(u8 *)(r6 +0)
; e->text[i] = ((char *)event_data)[i];
 207: (73) *(u8 *)(r0 +31) = r1
 208: (b7) r1 = 0
 209: (b7) r2 = 33
 210: (05) goto pc+51
 211: (0f) r3 += r1
 212: (73) *(u8 *)(r3 +0) = r4
; for (int i = 0; i < sizeof(check); i++) {
 213: (07) r1 += 1
; for (int i = 0; i < sizeof(check); i++) {
 214: (55) if r1 != 0x1e goto pc+47
; if (__builtin_memcmp(e->text, f.text, sizeof(check)) == 0) {
 215: (71) r2 = *(u8 *)(r10 -28)
 216: (67) r2 <<= 8
 217: (71) r1 = *(u8 *)(r10 -29)
 218: (4f) r2 |= r1
 219: (71) r3 = *(u8 *)(r10 -27)
 220: (67) r3 <<= 16
 221: (71) r1 = *(u8 *)(r10 -26)
 222: (67) r1 <<= 24
 223: (4f) r1 |= r3
 224: (71) r4 = *(u8 *)(r10 -32)
 225: (67) r4 <<= 8
 226: (71) r3 = *(u8 *)(r10 -33)
 227: (4f) r4 |= r3
 228: (71) r5 = *(u8 *)(r10 -31)
 229: (67) r5 <<= 16
 230: (71) r3 = *(u8 *)(r10 -30)
 231: (67) r3 <<= 24
 232: (4f) r3 |= r5
 233: (4f) r3 |= r4
 234: (4f) r1 |= r2
 235: (71) r4 = *(u8 *)(r0 +1)
 236: (67) r4 <<= 8
 237: (71) r2 = *(u8 *)(r0 +0)
 238: (4f) r4 |= r2
 239: (71) r5 = *(u8 *)(r0 +2)
 240: (67) r5 <<= 16
 241: (71) r2 = *(u8 *)(r0 +3)
 242: (67) r2 <<= 24
 243: (4f) r2 |= r5
 244: (67) r1 <<= 32
 245: (4f) r1 |= r3
 246: (4f) r2 |= r4
 247: (71) r3 = *(u8 *)(r0 +5)
 248: (67) r3 <<= 8
 249: (71) r4 = *(u8 *)(r0 +4)
 250: (4f) r3 |= r4
 251: (71) r4 = *(u8 *)(r0 +6)
 252: (67) r4 <<= 16
 253: (71) r5 = *(u8 *)(r0 +7)
 254: (67) r5 <<= 24
 255: (4f) r5 |= r4
 256: (4f) r5 |= r3
 257: (67) r5 <<= 32
 258: (4f) r5 |= r2
 259: (1d) if r5 == r1 goto pc+18
 260: (b7) r1 = 1
 261: (05) goto pc+137
 262: (bf) r3 = r10
 263: (07) r3 += -33
; f->text[i] = check[i] ^ 0x60;
 264: (18) r4 = map[id:148][0]+16
 266: (0f) r4 += r1
 267: (71) r4 = *(u8 *)(r4 +0)
; f->text[i] = check[i] ^ 0x60;
 268: (a7) r4 ^= 96
 269: (67) r4 <<= 56
 270: (c7) r4 s>>= 56
; if (f->text[i] >= 33 && f->text[i] <= 126) {
 271: (6d) if r2 s> r4 goto pc-61
; f->text[i] = 33 + ((f->text[i] + 14) % 94u);
 272: (07) r4 += 14
 273: (67) r4 <<= 32
 274: (77) r4 >>= 32
; f->text[i] = 33 + ((f->text[i] + 14) % 94u);
 275: (97) r4 %= 94
; f->text[i] = 33 + ((f->text[i] + 14) % 94u);
 276: (07) r4 += 33
 277: (05) goto pc-67
; if (__builtin_memcmp(e->text, f.text, sizeof(check)) == 0) {
 278: (71) r2 = *(u8 *)(r10 -20)
 279: (67) r2 <<= 8
 280: (71) r1 = *(u8 *)(r10 -21)
 281: (4f) r2 |= r1
 282: (71) r3 = *(u8 *)(r10 -19)
 283: (67) r3 <<= 16
 284: (71) r1 = *(u8 *)(r10 -18)
 285: (67) r1 <<= 24
 286: (4f) r1 |= r3
 287: (71) r4 = *(u8 *)(r10 -24)
 288: (67) r4 <<= 8
 289: (71) r3 = *(u8 *)(r10 -25)
 290: (4f) r4 |= r3
 291: (71) r5 = *(u8 *)(r10 -23)
 292: (67) r5 <<= 16
 293: (71) r3 = *(u8 *)(r10 -22)
 294: (67) r3 <<= 24
 295: (4f) r3 |= r5
 296: (4f) r3 |= r4
 297: (4f) r1 |= r2
 298: (71) r4 = *(u8 *)(r0 +9)
 299: (67) r4 <<= 8
 300: (71) r2 = *(u8 *)(r0 +8)
 301: (4f) r4 |= r2
 302: (71) r5 = *(u8 *)(r0 +10)
 303: (67) r5 <<= 16
 304: (71) r2 = *(u8 *)(r0 +11)
 305: (67) r2 <<= 24
 306: (4f) r2 |= r5
 307: (67) r1 <<= 32
 308: (4f) r1 |= r3
 309: (4f) r2 |= r4
 310: (71) r3 = *(u8 *)(r0 +13)
 311: (67) r3 <<= 8
 312: (71) r4 = *(u8 *)(r0 +12)
 313: (4f) r3 |= r4
 314: (71) r4 = *(u8 *)(r0 +14)
 315: (67) r4 <<= 16
 316: (71) r5 = *(u8 *)(r0 +15)
 317: (67) r5 <<= 24
 318: (4f) r5 |= r4
 319: (4f) r5 |= r3
 320: (67) r5 <<= 32
 321: (4f) r5 |= r2
 322: (5d) if r5 != r1 goto pc-63
 323: (71) r2 = *(u8 *)(r10 -12)
 324: (67) r2 <<= 8
 325: (71) r1 = *(u8 *)(r10 -13)
 326: (4f) r2 |= r1
 327: (71) r3 = *(u8 *)(r10 -11)
 328: (67) r3 <<= 16
 329: (71) r1 = *(u8 *)(r10 -10)
 330: (67) r1 <<= 24
 331: (4f) r1 |= r3
 332: (71) r4 = *(u8 *)(r10 -16)
 333: (67) r4 <<= 8
 334: (71) r3 = *(u8 *)(r10 -17)
 335: (4f) r4 |= r3
 336: (71) r5 = *(u8 *)(r10 -15)
 337: (67) r5 <<= 16
 338: (71) r3 = *(u8 *)(r10 -14)
 339: (67) r3 <<= 24
 340: (4f) r3 |= r5
 341: (4f) r3 |= r4
 342: (4f) r1 |= r2
 343: (71) r4 = *(u8 *)(r0 +17)
 344: (67) r4 <<= 8
 345: (71) r2 = *(u8 *)(r0 +16)
 346: (4f) r4 |= r2
 347: (71) r5 = *(u8 *)(r0 +18)
 348: (67) r5 <<= 16
 349: (71) r2 = *(u8 *)(r0 +19)
 350: (67) r2 <<= 24
 351: (4f) r2 |= r5
 352: (67) r1 <<= 32
 353: (4f) r1 |= r3
 354: (4f) r2 |= r4
 355: (71) r3 = *(u8 *)(r0 +21)
 356: (67) r3 <<= 8
 357: (71) r4 = *(u8 *)(r0 +20)
 358: (4f) r3 |= r4
 359: (71) r4 = *(u8 *)(r0 +22)
 360: (67) r4 <<= 16
 361: (71) r5 = *(u8 *)(r0 +23)
 362: (67) r5 <<= 24
 363: (4f) r5 |= r4
 364: (4f) r5 |= r3
 365: (67) r5 <<= 32
 366: (4f) r5 |= r2
 367: (5d) if r5 != r1 goto pc-108
 368: (71) r2 = *(u8 *)(r10 -8)
 369: (67) r2 <<= 8
 370: (71) r1 = *(u8 *)(r10 -9)
 371: (4f) r2 |= r1
 372: (71) r3 = *(u8 *)(r10 -7)
 373: (67) r3 <<= 16
 374: (71) r1 = *(u8 *)(r10 -6)
 375: (67) r1 <<= 24
 376: (4f) r1 |= r3
 377: (4f) r1 |= r2
 378: (71) r2 = *(u8 *)(r0 +25)
 379: (67) r2 <<= 8
 380: (71) r3 = *(u8 *)(r0 +24)
 381: (4f) r2 |= r3
 382: (71) r3 = *(u8 *)(r0 +26)
 383: (67) r3 <<= 16
 384: (71) r4 = *(u8 *)(r0 +27)
 385: (67) r4 <<= 24
 386: (4f) r4 |= r3
 387: (4f) r4 |= r2
 388: (5d) if r4 != r1 goto pc-129
 389: (71) r2 = *(u8 *)(r10 -4)
 390: (67) r2 <<= 8
 391: (71) r1 = *(u8 *)(r10 -5)
 392: (4f) r2 |= r1
 393: (71) r1 = *(u8 *)(r0 +28)
 394: (71) r3 = *(u8 *)(r0 +29)
 395: (67) r3 <<= 8
 396: (4f) r3 |= r1
 397: (b7) r1 = 0
 398: (5d) if r3 != r2 goto pc-139
 399: (b7) r2 = 1
; if (__builtin_memcmp(e->text, f.text, sizeof(check)) == 0) {
 400: (15) if r1 == 0x0 goto pc+1
 401: (b7) r2 = 0
 402: (73) *(u8 *)(r0 +32) = r2
; bpf_ringbuf_submit(e, 0);
 403: (bf) r1 = r0
 404: (b7) r2 = 0
 405: (85) call bpf_ringbuf_submit#311184
; }
 406: (b7) r0 = 2
 407: (95) exit
$ sudo /sbin/bpftool map dump id 159
key:
00 00 00 00
value:
57 34 72 70 00 00 00 00  00 00 00 00 00 00 00 00
24 26 5f 2c 5f 3f 5f 50  58 21 00 50 11 41 15 50
54 20 55 56 50 58 3f 50  53 23 23 23 23 2e
Found 1 element
```

We can see there is logic that processes data from the map:

```c
if (__builtin_memcmp(e->text, f.text, sizeof(check)) == 0) {
  f->text[i] = check[i] ^ 0x60;
  if (f->text[i] >= 33 && f->text[i] <= 126) {
    f->text[i] = 33 + ((f->text[i] + 14) % 94u);
    bpf_ringbuf_submit(e, 0);
  }
}
```

Solve script in python:

```python
b = bytes.fromhex("""24 26 5f 2c 5f 3f 5f 50  58 21 00 50 11 41 15 50
54 20 55 56 50 58 3f 50  53 23 23 23 23 2e
""")
s = bytes([ch ^ 0x60 for ch in b])
for ch in s:
    if ch >= 33 and ch <= 126:
        print(chr(33 + (ch + 14) % 94), end="")
    else:
        print(chr(ch), end="")
```

Flag: `sun{n0n_gp1_BPF_code_g0_brrrr}`.
