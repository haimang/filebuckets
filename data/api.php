<?php

include_once('data/init.php');
$pdo = new PDO('sqlite:data/filebucket.db');

$type=$_GET['type'];
$fun_arr=['login','logout','addUser','lists','download','upload','createFolder','upload','createFolder','rename','delete'];

if(in_array($type,$fun_arr)){
    print_r($_REQUEST);
    $type($pdo,$_REQUEST);
}
die;
switch($type){
    case 'login':

        break;
    case 'logout':

        break;
    case 'addUser':
        //添加账号
        $name=isset($_GET['name'])?$_GET['name']:null;
        $password=isset($_GET['password'])?$_GET['password']:null;
        $dir = 'users/'.$name;
        $path=isset($_GET['path'])?$_GET['path']:$dir;
        if(is_null($name) || is_null($password) ){
            echo  json_encode(['code'=>0,'message'=>'填写相关信息'],JSON_UNESCAPED_UNICODE);exit;
        }
        
        $stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");
        $stmt->execute([$name]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if($user){
            echo  json_encode(['code'=>0,'message'=>'用户已存在'],JSON_UNESCAPED_UNICODE);exit;
        }
        $result=registerUser($pdo,$name,$password,$path);
        mkdir($dir, 0777, true);
        echo  json_encode(['code'=>1,'message'=>'成功'],JSON_UNESCAPED_UNICODE);exit;

        break;
    case 'list':
        break;
    case 'download':
        break;
    case 'upload':

        break;
    case 'createFolder':
        break;
    case 'rename':
        break;
    case 'delete':
        break;
}

function login($pdo,$data){

}

function logout($pdo,$data) {

}

//添加账号
function addUser($pdo,$data){
    $name=isset($data['name'])?$data['name']:null;
    $password=isset($data['password'])?$data['password']:null;
    $dir = $name;
    $path=isset($data['path'])?$data['path']:$dir;
    if(is_null($name) || is_null($password) ){
        echo  json_encode(['code'=>0,'message'=>'填写相关信息'],JSON_UNESCAPED_UNICODE);
        exit;
    }

    $stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");
    $stmt->execute([$name]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if($user){
        echo  json_encode(['code'=>0,'message'=>'用户已存在'],JSON_UNESCAPED_UNICODE);
        exit;
    }
    $result=registerUser($pdo,$name,$password,$path);
    mkdir($dir, 0777, true);
    echo  json_encode(['code'=>1,'message'=>'成功'],JSON_UNESCAPED_UNICODE);
    exit;
}

function lists($pdo,$data){

}

function download($pdo,$data){
    
}

function upload($pdo,$data){
    
}

function createFolder($pdo,$data){
    
}
function delete($pdo,$data){
    
}

function rename11($pdo,$data){}



