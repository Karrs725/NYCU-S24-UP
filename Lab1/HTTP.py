from pwn import *
r = remote('ipinfo.io', 80)

r.sendline(b'GET /ip HTTP/1.1\r\nHost: ipinfo.io\r\nUser-Agent: curl/7.88.1\r\nAccept: */*\r\n')
resp = r.recvall()
print(resp[-15:])