# thrift-store

```
by Ciaran
Description

The frontend has gone down but the store is still open, can you buy the flag?

thrift-store.chal.imaginaryctf.org:9090
```

From the provided pcap, we can see that it is a thrift server with the following endpoints:

```thrift
# client.thrift
struct Basket {
  1: string basket,
}

struct GetBasketItem {
  1: string item,
  2: i8 count,
}

struct GetBasket {
  1: list<GetBasketItem> items,
}

struct InventoryItem {
  1: string item,
  2: string name,
  3: i64 number,
  4: string desc,
}

struct Inventory {
  1: list<InventoryItem> items,
}

service Test {
  Basket createBasket();
  void addToBasket(1:string basket, 2:string item);
  GetBasket getBasket(1:string basket);
  Inventory getInventory();
  void pay(1:string basket, 2:i64 number);
}
```

We can see that there is a `flag` in the inventory. Add it to basket and pay for it:

```python
# thrift-client.py
import sys
import glob
sys.path.append('gen-py')

from client import Test

from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

transport = TSocket.TSocket('thrift-store.chal.imaginaryctf.org', 9090)
transport = TTransport.TFramedTransport(transport)
protocol = TBinaryProtocol.TBinaryProtocol(transport)
client = Test.Client(protocol)

transport.open()

basket = client.createBasket().basket
print(basket)
print(client.getInventory())

item = "flag"
client.addToBasket(basket, item)
print(client.getBasket(basket))
print(client.pay(basket, 9999))
```

```shell
$ thrift -r --gen py client.thrift && python3 thrift-client.py
1ec5c183-7d17-41a0-90c0-810aa62348c1
Inventory(items=[InventoryItem(item='apple-red-delicious', name='Red Delicious Apple', number=120, desc='Crisp and sweet red apples, perfect for snacking.'), InventoryItem(item='banana', name='Banana', number=90, desc=None), InventoryItem(item='whole-milk-1l', name='Whole Milk (1L)', number=250, desc='Fresh whole milk sourced from local farms.'), InventoryItem(item='brown-eggs-dozen', name='Brown Eggs (Dozen)', number=450, desc=None), InventoryItem(item='bread-sourdough-loaf', name='Sourdough Bread Loaf', number=500, desc='Artisan sourdough with a crispy crust.'), InventoryItem(item='carrots-1kg', name='Carrots (1kg)', number=300, desc=None), InventoryItem(item='chicken-breast-500g', name='Chicken Breast (500g)', number=750, desc='Lean chicken breast, skinless and boneless.'), InventoryItem(item='rice-basmati-1kg', name='Basmati Rice (1kg)', number=600, desc=None), InventoryItem(item='olive-oil-500ml', name='Extra Virgin Olive Oil (500ml)', number=1200, desc='Cold-pressed, premium quality olive oil.'), InventoryItem(item='cheddar-cheese-200g', name='Cheddar Cheese (200g)', number=550, desc=None), InventoryItem(item='tomatoes-500g', name='Tomatoes (500g)', number=280, desc='Juicy ripe tomatoes, great for salads.'), InventoryItem(item='onions-1kg', name='Onions (1kg)', number=250, desc=None), InventoryItem(item='orange-juice-1l', name='Orange Juice (1L)', number=400, desc='100% pure squeezed orange juice.'), InventoryItem(item='potatoes-2kg', name='Potatoes (2kg)', number=350, desc=None), InventoryItem(item='yogurt-plain-500g', name='Plain Yogurt (500g)', number=320, desc='Thick and creamy natural yogurt.'), InventoryItem(item='flag', name='Flag', number=9999, desc=None)])
GetBasket(items=[GetBasketItem(item='flag', count=1)])
Pay(flag='ictf{l1k3_gRPC_bUt_l3ss_g0ogly}')
```

Get flag: `ictf{l1k3_gRPC_bUt_l3ss_g0ogly}`