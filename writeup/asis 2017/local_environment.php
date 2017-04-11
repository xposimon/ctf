<?php 

class log {

    protected $_method = 'toString';

    function __toString(){
        return $this->{$this->_method}();
    }
}

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
class logFile extends log {
	private $__logName = '../includes/configuration.php';
	
	protected $_method = 'readLog';

}
class MysqliDb
{
	protected static $_instance;

    public static $prefix = '';
    protected $_mysqli;

    protected $_query;


    protected $_lastQuery;


    protected $_join = array();

    protected $_where = array();


    protected $_joinAnd = array();


    protected $_having = array();

    protected $_orderBy = array();


    protected $_groupBy = array();


    protected $_tableLocks = array();


    protected $_tableLockMethod = "READ";


    protected $_bindParams = array(''); // Create the empty 0 index


    public $count = 0;


    public $totalCount = 0;

    protected $_stmtError;


    protected $_stmtErrno;

 
    protected $host;
    protected $_username;
    protected $_password;
    protected $db;
    protected $port;
    protected $charset;


    protected $isSubQuery = false;

    protected $_lastInsertId = null;


    protected $_updateColumns = null;


    public $returnType = 'array';

    protected $_nestJoin = false;


    private $_tableName = '';

    protected $_forUpdate = false;

    protected $_lockInShareMode = false;

    protected $_mapKey = null;

    protected $traceStartQ;
    protected $traceEnabled;
    protected $traceStripPrefix;
    public $trace = array();


    public $pageLimit = 20;

    public $totalPages = 0;
	protected $_queryOptions = array('*','from','credentials#');
public function __construct($host = null, $username = null, $password = null, $db = null, $port = null, $charset = 'utf8')
    {
        $isSubQuery = false;

        // if params were passed as array
        if (is_array($host)) {
            foreach ($host as $key => $val) {
                $$key = $val;
            }
        }
        // if host were set as mysqli socket
        if (is_object($host)) {
            $this->_mysqli = $host;
        } else {
            $this->host = $host;
        }

        $this->_username = $username;
        $this->_password = $password;
        $this->db = $db;
        $this->port = $port;
        $this->charset = $charset;

        if ($isSubQuery) {
            $this->isSubQuery = true;
            return;
        }

        if (isset($prefix)) {
            $this->setPrefix($prefix);
        }

        self::$_instance = $this;
    }
	
}
if (isset($_POST['filename']))
{
	$a = new logFile();
	$payload = array('logged'=>true, 'title'=>'mr.','username'=>$a);
	var_dump(serialize($payload));
	file_put_contents('test.out', serialize($payload));
}
else if (isset($_POST['db']))
{
	$a = new MysqliDb('localhost', 'user', 'password', 'ultraSecured');
	$b = new logDB($a);
	$payload = array('logged'=>true, 'title'=>'mr.','username'=>$b);
	file_put_contents('test.out', serialize($payload));
}
else {
$__sessionKey = 'THEKEYISHEREWOW!';
if(array_key_exists('auth', $_GET))
   	$sessionString = $_GET['auth'];

if(strlen($sessionString) > 32){
    $signature = substr($sessionString, -32);
    $payload = base64_decode(substr($sessionString, 0, -32));

    $realSign = md5($payload.$__sessionKey);

    
    $realSign = substr($realSign, 0, 6);

    
    if($realSign == $signature){
    	//echo $payload;
        $data = unserialize($payload);

        if(is_array($data)){
            
            if($data['logged']===true){
                $__auth = true;
                var_dump($data);
            }
        }
    }
    else{
    	echo 'login required';
    	}
	}
}

?>
