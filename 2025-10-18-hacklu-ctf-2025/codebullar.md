# CÖDEBULLAR

```
FLUX offers some culinary delights to ensure that not only your shopping cart, but also your belly is full...
```

Attachment:

```python
import os
import random
from PIL import Image

köttbullar_dir = './assets/köttbullar'
hotdogs_dir = './assets/hotdogs'
output_dir = './encoded'
os.makedirs(output_dir, exist_ok=True)

köttbullar_files = [os.path.join(köttbullar_dir, f) for f in os.listdir(köttbullar_dir)]
hotdogs_files = [os.path.join(hotdogs_dir, f) for f in os.listdir(hotdogs_dir)]

with open('./secret.txt', 'r') as f:
    FLAG = f.read().strip()

bin_str = ''.join(format(ord(c), '08b') for c in FLAG)

for i, bit in enumerate(bin_str):
    src = random.choice(köttbullar_files) if bit == '0' else random.choice(hotdogs_files)
    dst = os.path.join(output_dir, f'{i:04}.jpeg')
    with Image.open(src) as img:
        img.save(dst, format='JPEG', quality=95)

print(f'Encoded {len(bin_str)} bits with CODEBULLAR encoding')
```

For each bit in secret string, an image of `köttbullar` or `hotdog` is copied to the output directory. We classify each image by its size and recover each bit:

```python
import os

bits = []
for i in range(5536):
    name = f"encoded/{i:04}.jpeg"
    size = os.stat(name).st_size
    if size in [
        54642,
        71086,
        57802,
        48757,
        80501,
        31508,
        82768,
        53381,
        37928,
        44093,
        37165,
        29078,
        82914,
        24754,
        61314,
        96042,
    ]:
        bits.append(1)
    elif size in [
        81647,
        89397,
        70505,
        83744,
        33819,
        39204,
        72016,
        75897,
        75869,
        49256,
        109790,
        64823,
        77106,
        78095,
        58614,
        77109,
    ]:
        bits.append(0)
    else:
        print(name, size)

data = bytes(
    [sum([byte[b] << (7 - b) for b in range(0, 8)]) for byte in zip(*(iter(bits),) * 8)]
)

print(data)
```

Output:

```
b'Hotdogs are sausages served in soft buns, typically made from beef, pork, or chicken. They are often topped with mustard, ketchup, onions, or relish. The world record HPM (Hotdogs per Minute) is 6, achieved by Miki Sudo. The flag for this challenge is flag{w3_0bv10u5ly_n33d3d_4_f00d_ch4113n93}. K\xf6ttbullar are Swedish meatballs made from ground beef and pork, mixed with breadcrumbs, egg, and spices. They are usually served with creamy gravy, lingonberry jam, and boiled potatoes. According to the swedish government, k\xf6ttbullar are based on a recipe King Karl XII brought home from the ottoman empire. However, the Swedish food historian Richard Tellstr\xf6m says this claim is a modern myth.'
```

Flag: `flag{w3_0bv10u5ly_n33d3d_4_f00d_ch4113n93}`.
