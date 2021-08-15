# Easy Xchange

这题是要找到下面代码的 BUG：

```python
import os, hashlib, pickle
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = os.urandom(4)
FLAG = open('flag.txt', 'rb').read()
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = p - 3
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

def gen_key(G, pvkey):
	G = sum([i*G for i in pvkey])
	return G

def encrypt(msg, key):
	key = hashlib.sha256(str(key).encode()).digest()[:16]
	cipher = AES.new(key, AES.MODE_CBC, os.urandom(16))
	return {'cip': cipher.encrypt(pad(msg, 16)).hex(), 'iv': cipher.IV.hex()}

def gen_bob_key(EC, G):
	bkey = os.urandom(4)
	B = gen_key(G, bkey)
	return B, bkey

def main():
	EC = EllipticCurve(GF(p), [a, b])
	G = EC.gens()[0]
	Bx = int(input("Enter Bob X value: "))
	By = int(input("Enter Bob Y value: "))
	B = EC(Bx, By)
	P = gen_key(G, key)
	SS = gen_key(B, key)
	cip = encrypt(FLAG, SS.xy()[0])
	cip['G'] = str(G)
	return cip

if __name__ == '__main__':
	cip = main()
	pickle.dump(cip, open('enc.pickle', 'wb'))
```

模仿了 DH 密钥交换的过程：Bob 自己生成了一个密钥 $B=P_b*G$，然后输入到 main，再计算 $SS=P_a*B=P_a\*P_b\*G$，以此作为密钥加密 FLAG。观察代码可以发现，虽然随机了 4 个 8 字节数，但是因为求和的性质，实际上求和的范围只有 0~1024；意味着，只需要枚举 1024*1024 种可能即可：

```python
import os, hashlib, pickle
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = p - 3
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

cip = '9dcc2c462c7cd13d7e37898620c6cdf12c4d7b2f36673f55c0642e1e2128793676d985970f0b5024721afaaf02f2f045'
iv = 'cbd6c57eac650a687a7c938d90e382aa'
# 'G': '(38764697308493389993546589472262590866107682806682771450105924429005322578970 : 112597290425349970187225006888153254041358622497584092630146848080355182942680 : 1)'}

EC = EllipticCurve(GF(p), [a, b])
G = EC.gens()[0]

def decrypt(key):
	key = hashlib.sha256(str(key).encode()).digest()[:16]
	cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv))
	data = cipher.decrypt(bytes.fromhex(cip))
	try:
		res = unpad(data, 16)
		return res
	except:
		return []

#point = G * 420462
#res = decrypt(point.xy()[0])
#print(res)
#exit()

i = 1
point = G
while i <= 1024 * 1024:
	res = decrypt(point.xy()[0])
	if res != []:
		print(i, len(res), res)
	i = i + 1
	point = point + G
```

运行一段时间后输出，会输出很多错误结果，在其中搜索 inctf 即可找到 FLAG：

```
420462 42 b'inctf{w0w_DH_15_5o_c00l!_3c9cdad74c27d1fc}'
```

可知 $SS=420462*G$，去掉上面代码中的注释就可以直接解密。