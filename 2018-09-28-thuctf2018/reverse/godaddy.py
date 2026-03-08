from pwn import *
e = ELF('./godaddy')
with open('godaddy.txt', 'r') as fd:
    lines = fd.readlines()
    for line in lines:
        line = line.strip()
        if not len(line):
            continue
        address = int(line[:line.find(',')],16)
        code = int(line[line.find(',')+1:],16)
        print '%x %x' % (address, code)
        e.p64(address, code)

e.save('./godaddy_new')
