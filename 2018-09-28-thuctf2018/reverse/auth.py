from pwn import *
r = remote('202.112.51.234', 20000)
r.sendline('version 3.11.54')
cid = r.recvline()
nonce = cid[15:-1]
rand_num = nonce[7]
mutator = 1
ecx = ord(rand_num[0])
# ecx = ecx % 3
user = 'iromise'
#from nonce[var_14] to dest for 5 bytes
var_14 = (ecx % 3)+ mutator
dest = nonce[var_14:var_14+len(user)]
#for each i
s = []
for i in range(0, len(user)):
    esi = ord(dest[i]) # $rbp-0x10
    rax = ord(user[i]) # *(long*)($rbp-0x28)
    s.append((esi^rax)-i) # *(long*)($rbp-0x30)
    # > 0x7E then sub 0x7E
    # < 32 then add 32
    if s[i] > 0x7E:
        s[i] -= 0x7E
    if s[i] < 0x20:
        s[i] += 0x20
    s[i] = chr(s[i])
s = ''.join(s)
r.sendline(user)
r.sendline(s)
r.sendline('list users')
r.sendline('print key')
challenge = r.recvline_startswith('challenge:')[11:]
print repr(challenge)
mutator = 7
var_14 = (ecx % 3)+ mutator
dest = nonce[var_14:var_14+len(challenge)]
#for each i
s = []
for i in range(0, len(challenge)):
    esi = ord(dest[i]) # $rbp-0x10
    rax = ord(challenge[i]) # *(long*)($rbp-0x28)
    s.append((esi^rax)-i) # *(long*)($rbp-0x30)
    # > 0x7E then sub 0x7E
    # < 32 then add 32
    if s[i] > 0x7E:
        s[i] -= 0x7E
    if s[i] < 0x20:
        s[i] += 0x20
    s[i] = chr(s[i])
s = ''.join(s)
print repr(s)
r.sendline(s)
r.interactive()
