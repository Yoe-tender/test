import requests
url = 'http://160.202.254.160:14094'
s = requests.Session()
source = s.get(url)
a = '0123456789+-*'
c = ''
for i in source.text[158:277]:
    if i in a:
        c += i
post = {'value':eval(c)}
print(s.post(url,data = post).text)