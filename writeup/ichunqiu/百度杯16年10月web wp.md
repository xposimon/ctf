##Login
key: array_merge函数相同键后面会覆盖前面
打开页面查看源码往下翻 test1 test1是账号密码、（脑洞不够。。。）
登录进去member.php 响应头有一个show: 0, 把0改成1发回去
添加一个show: 1请求头发送回去，(这个show参数也有可能是get，post回去。甚至文件上传回去。。)
得到源码
<?php
	include 'common.php';
	$requset = array_merge($_GET, $_POST, $_SESSION, $_COOKIE);
if(isset($requset['token']))
	{
		$login = unserialize(gzuncompress(base64_decode($requset['token'])));
		$db = new db();
		$row = $db->select('user=\''.mysql_real_escape_string($login['user']).'\'');
		if($login['user'] === 'ichunqiu')
		{
			echo $flag;
		}else if($row['pass'] !== $login['pass']){
			echo 'unserialize injection!!';
		}else{
			echo "(â¯âµâ¡â²)â¯ï¸µâ´ââ´ ";
		}
	}else{
		header('Location: index.php?error=1');
	}
这个地方array_merge函数后面的session有token这个键值，所以会覆盖前面的键。。所以必须要用cookie中添加token函数。（其实在访问member.php页面没有发生location: index.php?error=1就应该反应过来session里面是有token键的，因为get，post，cookie中都没有。不然一定会跳转）

##GetFlag
KEY: download 过滤.. / 用绝对路径替换
进入页面有一个验证码，直接用数字暴力碰撞就好。
username用万能密码直接登录
action.php?action=file, 存在下载页面
/file/download.php?f=a.php
但是过滤了../，直接用默认根目录 /var/www/html下载flag.php（有提示flag在根目录）
然后就是做过的字符串只能用<符号。定界符即可


##Backdoor
Key: git泄露
用工具把git目录下载。切换分支到flag.php文件修改之前，找到提示。然后.b4ckdo0r.php.swo文件泄露。找到源码。（没有mac恢复不了。。。）

##Fuzzing
key： fuzz+脑洞
一开始test.php的提示在response header里面， hint：large internal network
换client-ip到10.0.0.1大型内网的ip
得到下一个网页/m4nage.php
 显示show me your key。。。
说明要传一个key参数。。get，post，header，upfile。。都试一遍
发现需要上传文件有一个key参数,  然后得到
key is not right,md5(key)==="1b4167610ba3f2ac426a68488dbd89be",and the key is ichunqiu***,the * is in [a-z0-9]
cmd5 直接解密:ichunqiu105
把key上传的内容改为ichunqiu105
得到xx00xxoo.php页面，403响应
猜测需要验证，验证就是key。所以把上传文件的key加上。得到
source code is in the x0.txt.Can you guess the key
the authcode(flag) is bebfgNaof1nC+KsF+A150Ceb7VOzvBkMA+ReKhEQoyXJFwrXJxNydJE+fTwqXa7Q4GGVMBFb2zuTsuTiYboux2qqSgVCH10
拿到源码，是一个解密的函数。直接调用就行了得到flag
