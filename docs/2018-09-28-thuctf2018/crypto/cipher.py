#!/usr/bin/env python3
# https://github.com/VoidHack/write-ups/tree/master/SharifCTF%208/crypto/DES
from Crypto.Cipher import DES
import sys
cipher = "8fb92ee53079e973327c73c3e779a010257806e32ef35f38"
key = ["0101010101010101", "FEFEFEFEFEFEFEFE", "E0E0E0E0F1F1F1F1", "1F1F1F1F0E0E0E0E"]
mapping = dict()
with open('ciphertexts.txt', 'r') as fd:
    lines = fd.readlines()
    for line in lines:
        plain = line[:16]
        c = line[17:-1]
        mapping[plain] = c
weak = None
for i in mapping.keys():
    c = mapping[i]
    if c in mapping:
        print i, ' -> ', c 
        print c, ' -> ', mapping[c]
        weak = c
# weak keys!
for i in key:
    des = DES.new(i.decode('hex'), DES.MODE_ECB)
    cur = weak.decode('hex')
    try:
        for j in range(0, 101):
            cur = des.decrypt(cur)
    except:
        print sys.exc_info()
    if cur == mapping[weak].decode('hex'):
        for k in range(0, 3):
            cur = cipher[k*16:(k+1)*16].decode('hex')
            try:
                for j in range(0, 101):
                    cur = des.decrypt(cur)
            except:
                print sys.exc_info()
            print cur
