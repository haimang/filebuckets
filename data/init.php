<?php
include_once "sqlite.class.php";

function registerUser($db, $username, $password, $path = '',$email='',$type='',$delete_perm='')
{
    // 插入用户到数据库
    $stmt = $db->prepare("INSERT INTO users (hash,name, password,path,email,type,delete_perm,add_time,update_time) VALUES (?,?,?,?,?,?,?,?,?)");
    if($username=='admin'){
        $hash =create_hash('user','admin');
    }else{
        $hash =create_hash('user','third');
    }

    // 生成 密码 md5(hash+password)
    $hashedPassword = md5($hash.$password);
    $time=date('Y-m-d H:i:s');
    
    $stmt->execute([$hash,$username, $hashedPassword, $path,$email,$type,$delete_perm,$time,$time]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    $stmt = $db->prepare("SELECT * FROM users WHERE name = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    return $user;
}

// 用户登录的例子
function loginUser($db, $username, $password)
{
    $stmt = $db->prepare("SELECT * FROM users WHERE name = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    //密码 md5(hash+password)
    if ($user && md5($user['hash'].$password)==$user['password']) {
        // 密码匹配，用户登录成功
        return ['code'=>1,'data'=>$user];
    }
    return ['code'=>0,'data'=>false];
}
//文件数据插入
function addFile($db,$u_hash,$name,$type='file',$path=null){
    $hash =create_hash('document',$type);
    $time=date('Y-m-d H:i:s');
    //$f_hash=null;
    
    // 插入文件数据
    $stmt = $db->prepare("INSERT INTO files (hash,u_hash,name,type,path,add_time, update_time) VALUES (?,?,?,?,?,?,?)");
    $stmt->execute([$hash,$u_hash,$name, $type, $path,$time,$time]);
    $file = $stmt->fetch(PDO::FETCH_ASSOC);
    return $file;
}

//文件数据修改-文件名修改
function updateFile($db,$u_hash,$name,$newName,$path=null){
    //修改时间更新
    $stmt = $db->prepare("UPDATE files SET name=?,update_time=?  WHERE u_hash = ? AND name=? AND path=?");
    $update_time=date('Y-m-d H:i:s');
    $stmt->execute([$newName,$update_time,$u_hash,$name, $path]);

    $stmt = $db->prepare("SELECT * FROM files WHERE u_hash = ? AND name=? AND path=?");
    $stmt->execute([$u_hash,$name, $path]);
    $info = $stmt->fetch(PDO::FETCH_ASSOC);
    return $info;
}

//文件数据修改-文件目录修改
function updateFolder($db,$u_hash,$hash,$path){
    //修改时间更新
    $stmt = $db->prepare("UPDATE files SET path=?,update_time=?  WHERE u_hash = ? AND hash=?");
    $update_time=date('Y-m-d H:i:s');
    $stmt->execute([$path,$update_time,$u_hash,$hash]);

    $stmt = $db->prepare("SELECT * FROM files WHERE u_hash = ? AND hash=?");
    $stmt->execute([$u_hash,$hash]);
    $info = $stmt->fetch(PDO::FETCH_ASSOC);
    return $info;
}

//搜索
function getSearchFile($db,$u_hash,$keyword) {
    
}

//获取当前文件
function getFile($db,$u_hash,$name,$path=null) {
    $stmt = $db->prepare("SELECT * FROM files WHERE  u_hash = ? AND name=? AND path=?");
    $stmt->execute([$u_hash,$name, $path]);
    $file = $stmt->fetch(PDO::FETCH_ASSOC);
    return $file;
}

//文件数据删除
function deleteFile($db,$u_hash,$name=null,$path=null) {
    if(is_null($name)){
        $stmt = $db->prepare("DELETE FROM files WHERE u_hash = ?  AND path like ?");
        $stmt->execute([$u_hash,$path]);
    }else{
        $stmt = $db->prepare("DELETE FROM files WHERE u_hash = ? AND name=? AND path=?");
        $stmt->execute([$u_hash,$name, $path]);
    }
    
    return true;
}

function random_str($type = 'alphanum', $length = 8)
{
    switch ($type) {
        case 'basic':return mt_rand();
            break;
        case 'alpha':
        case 'alphanum':
        case 'num':
        case 'nozero':
            $seedings = array();
            $seedings['alpha'] = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
            $seedings['alphanum'] = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
            $seedings['num'] = '0123456789';
            $seedings['nozero'] = '123456789';

            $pool = $seedings[$type];

            $str = '';
            for ($i = 0; $i < $length; $i++) {
                $str .= substr($pool, mt_rand(0, strlen($pool) - 1), 1);
            }
            return $str;
            break;
        case 'unique':
        case 'md5':
            return md5(uniqid(mt_rand()));
            break;
    }
}

//功能模块简称{2位}+类型{2位}+月日时分{4位}+四位随机字符
function create_hash($model,$type){
    $str='';
    $config = @file_get_contents($_SERVER['DOCUMENT_ROOT'].'/data/config.json');
    $config=json_decode($config,true);
    if(isset($config['hash']['prefix'][$model])){
        $str.=$config['hash']['prefix'][$model];
    }else{
        if($model=='document'){
            $str.='DM';
        }elseif($model=='user'){
            $str.='UR';
        }else{
            $str.='ST';
        }
    }
    
    if(empty($type)){
        $str.='00';
    }else{
        if(isset($config['hash']['type'][$type])){
            $str.=$config['hash']['type'][$type];
        }else{
            $str.='00';
        }
    }

    $month= date('m');
    $str.=$config['hash']['month'][$month];
    $day= date('d');
    $str.=$config['hash']['day'][$day];
    $hour= date('H');
    $str.=$config['hash']['hour'][$hour];
    $minute= date('i');
    $str.=$config['hash']['minute'][$minute];

    $random=random_str('alphanum', 4);
    $str.=$random;
    return $str;
}


$sqlSelect = <<<EOF
          SELECT * from users;
EOF;

$db = new sqliteDB("data/test.db");

/*
 * $db = new sqliteDB(':memory:');
 * 如果文件名赋值为':memory:'，那么 SQLite3::open() 将会在
 * RAM 中创建一个内存数据库，这只会在 session 的有效时间内持续。
 */
$isNull = false;
foreach ($db->queryDB($sqlSelect) as $value) {
    if ($value["name"] == 'admin') {
        $isNull = true;
    }
}

if (!$isNull) {
    //增加数据
    $auth_users = array(
        array('name' => 'admin', 'password' => 'a123456', 'path' => '','email'=>'admin@haimang.com','type'=>'admin'),
        array('name' => 'user', 'password' => '123456', 'path' => 'user','email'=>'user@haimang.com','type'=>'third'),
    );
    $pdo = new PDO('sqlite:data/test.db');
    foreach ($auth_users as $item) {
        //echo $user['name'];die;
        $user=registerUser($pdo, $item['name'], $item['password'], $item['path'],$item['email'],$item['type']);
        //print_r($user);die;
        if(!empty($item['path'])){
            //对应文件夹的创建
            if (!is_dir($item['path'])){
                mkdir($item['path'], 0777, true);
            }
            //添加数据入库
            addFile($pdo,$user['hash'],$item['path'], 'folder');
        }
    }
}
//删除数据
//$db->execute($sqliteDelete);
//修改数据
//$db->execute($sqlUpdata);
//查询数据
/* $res = $db->queryDB($sqlSelect);
if ($res) { */
   return $isNull;
/* } else {
   return false;
} */
