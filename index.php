<?php
include_once "./data/routes.php";

//初始化时生成基本的用户表
include_once "./data/init.php";
$pdo = new PDO('sqlite:data/filebucket.db');

define('VERSION', '0.0.1');

define('APP_TITLE', 'File');

$default_timezone = 'Asia/Shanghai'; // UTC

$iconv_input_encoding = 'UTF-8';

$datetime_format = 'Y/m/d H:i:s';

$max_upload_size_bytes = 5000000000; // size 5,000,000,000 bytes (~5GB)

$upload_chunk_size_bytes = 2000000; // chunk size 2,000,000 bytes (~2MB)

$global_readonly = false;

// e.g. 'txt,html,css,js'
$allowed_file_extensions = '';

// e.g. 'gif,png,jpg,html,txt'
$allowed_upload_extensions = '';

$use_highlightjs = true;

// highlight.js style
// for dark theme use 'ir-black'
$highlightjs_style = 'vs';

// Enable ace.js (https://ace.c9.io/) on view's page
$edit_files = true;

$favicon_path = '';

// Files and folders to excluded from listing
// e.g. array('myfile.html', 'personal-folder', '*.php', ...)
$exclude_items = array();

// Online office Docs Viewer
// Availabe rules are 'google', 'microsoft' or false
// Google => View documents using Google Docs Viewer
// Microsoft => View documents using Microsoft Web Apps Viewer
// false => disable online doc viewer
$online_viewer = 'Microsoft';

// Sticky Nav bar
// true => enable sticky header
// false => disable sticky header
$sticky_navbar = true;

//不可以显示的目录
$folders_not_display = array('data','.git');
//不可显示的文件
$file_not_display = array('index.php', '.htaccess', 'tinyfilemanager.php','.gitignore');

define('MAX_UPLOAD_SIZE', $max_upload_size_bytes);

define('UPLOAD_CHUNK_SIZE', $upload_chunk_size_bytes);

if (!defined('FM_SESSION_ID')) {
    define('FM_SESSION_ID', 'hcfile');
}

$lang = 'en';

$show_hidden_files = true;

$report_errors = true;

$hide_Cols = true;

if ($report_errors == true) {
    @ini_set('error_reporting', E_ALL);
    @ini_set('display_errors', 1);
} else {
    @ini_set('error_reporting', E_ALL);
    @ini_set('display_errors', 0);
}

// if fm included
if (defined('FM_EMBED')) {
    $use_auth = false;
    $sticky_navbar = false;
} else {
    @set_time_limit(600);

    date_default_timezone_set($default_timezone);

    ini_set('default_charset', 'UTF-8');
    if (version_compare(PHP_VERSION, '5.6.0', '<') && function_exists('mb_internal_encoding')) {
        mb_internal_encoding('UTF-8');
    }
    if (function_exists('mb_regex_encoding')) {
        mb_regex_encoding('UTF-8');
    }

    session_cache_limiter('nocache'); // Prevent logout issue after page was cached
    session_name(FM_SESSION_ID );
    function session_error_handling_function($code, $msg, $file, $line) {
        // Permission denied for default session, try to create a new one
        if ($code == 2) {
            session_abort();
            session_id(session_create_id());
            @session_start();
        }
    }
    set_error_handler('session_error_handling_function');
    session_start();
    restore_error_handler();
}

$theme = 'light';
if(isset($_GET['theme']) || isset($_SESSION['theme'])){
    if(isset($_GET['theme'])){
        $theme=$_GET['theme'];
        $_SESSION['theme']=$theme;
    }else{
        $theme=$_SESSION['theme'];
    }
}

define('FM_THEME', $theme);

//Generating CSRF Token
if (empty($_SESSION['token'])) {
    if (function_exists('random_bytes')) {
        $_SESSION['token'] = bin2hex(random_bytes(32));
    } else {
        $_SESSION['token'] = bin2hex(openssl_random_pseudo_bytes(32));
    }
}

$root_path = $_SERVER['DOCUMENT_ROOT'];

$is_https = isset($_SERVER['HTTPS']) && ($_SERVER['HTTPS'] == 'on' || $_SERVER['HTTPS'] == 1)
|| isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https';

$root_url = '';

$http_host = $_SERVER['HTTP_HOST'];

if (isset($_SESSION[FM_SESSION_ID]['logged'])) {
    $wd = fm_clean_path(dirname($_SERVER['PHP_SELF']));
    $root_url = $root_url . $wd . DIRECTORY_SEPARATOR ;
}

$root_url = fm_clean_path($root_url);

defined('FM_ROOT_URL') || define('FM_ROOT_URL', ($is_https ? 'https' : 'http') . '://' . $http_host . (!empty($root_url) ? '/' . $root_url : ''));
defined('FM_SELF_URL') || define('FM_SELF_URL', ($is_https ? 'https' : 'http') . '://' . $http_host . $_SERVER['PHP_SELF']);

$external = array(
    'logo' => 'data/dist/image/logo.png',
    'css-tabler' => '<link href="data/dist/css/tabler.min.css" rel="stylesheet"/>',
    'css-tabler-flags' => '<link href="data/dist/css/tabler-flags.min.css" rel="stylesheet"/>',
    'css-tabler-payments' => '<link href="data/dist/css/tabler-payments.min.css" rel="stylesheet"/>',
    'css-tabler-vendors' => '<link href="data/dist/css/tabler-vendors.min.css" rel="stylesheet"/>',
    'css-style' => '<link href="data/dist/css/style.min.css" rel="stylesheet"/>',
    'css-dropzone' => '<link href="data/dist/css/dropzone.css" rel="stylesheet"/>',
    'css-toastr' => '<link href="data/dist/css/toastr.min.css" rel="stylesheet"/>',
    'css-datatables'=>'<link rel="stylesheet" href="https://cdn.bootcdn.net/ajax/libs/datatables.net-bs4/3.2.2/dataTables.bootstrap4.min.css" />',
    'js-toastr' => '<script src="data/dist/js/toastr.min.js"></script>',
    'js-tabler' => '<script src="data/dist/js/tabler.min.js"></script>',
    'js' => '<script src="data/dist/js/demo.min.js"></script>',
    'js-list' => '<script src="data/dist/js/list.min.js"></script>',
    'js-dropzone' => '<script src="data/dist/js/dropzone-min.js"></script>',
    'js-bootstrap'=>'<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js"></script>',
    'js-jquery' => '<script src="https://code.jquery.com/jquery-3.6.1.min.js" integrity="sha256-o88AwQnZB+VDvE9tvIXrMQaPlFFSUTR+nldQm1LuPXQ=" crossorigin="anonymous"></script>',
    'js-jquery-datatables' => '<script src="https://cdn.datatables.net/1.13.1/js/jquery.dataTables.min.js" crossorigin="anonymous" defer></script>',
    'js-bootstrap-datatables'=>'<script type="text/javascript" src="https://cdn.datatables.net/1.10.25/js/dataTables.bootstrap4.min.js"></script>',
    'icon-2000' => 'http://www.w3.org/2000/svg',
);

// logout
if (isset($_GET['logout'])) {
    unset($_SESSION[FM_SESSION_ID]['logged']);
    unset($_SESSION[FM_SESSION_ID]);
    unset($_SESSION['token']);
    fm_redirect(FM_SELF_URL);
}

$editFile;

$use_auth = true;

if($use_auth){
    // login
    if (isset($_SESSION[FM_SESSION_ID]['logged'])){
        
    }else if(isset($_POST['f_name'], $_POST['f_password'], $_POST['token'])) {
        //登录表单提交
        if (function_exists('password_verify')) {
            $result = loginUser($pdo, $_POST['f_name'], $_POST['f_password']);
            
            if ($result['code'] == 1) {
                $_SESSION[FM_SESSION_ID]['logged'] = $_POST['f_name'];
                $_SESSION[FM_SESSION_ID]['path'] = $result['data']['path'];
                $_SESSION[FM_SESSION_ID]['hash'] = $result['data']['hash'];
                $_SESSION[FM_SESSION_ID]['user'] = $result['data'];

                //admin 初始密码是changeme 直接弹框修改密码，才能进行后面的存在
                if($_POST['f_name']=='admin' && $_POST['f_password']=='changeme'){
                    $_SESSION[FM_SESSION_ID]['is_first'] = 1;
                }else{
                    $_SESSION[FM_SESSION_ID]['is_first'] = 0;
                }

                fm_redirect(FM_SELF_URL);
            } else {
                unset($_SESSION[FM_SESSION_ID]['logged']);
                fm_redirect(FM_SELF_URL);
            }
        } else {
            fm_set_msg(lng('password_hash not supported, Upgrade PHP version'), 'error');
        }
    }else{
        unset($_SESSION[FM_SESSION_ID]);
        $getTheme = fm_get_theme();
        //登录界面开始
        ?>
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8"/>
            <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"/>
            <meta http-equiv="X-UA-Compatible" content="ie=edge"/>
            <title><?php echo fm_enc(APP_TITLE) ?></title>
            <?php print_external('css-tabler');?>
            <?php print_external('css-tabler-flags');?>
            <?php print_external('css-tabler-payments');?>
            <?php print_external('css-tabler-vendors');?>
            <?php print_external('css-style');?>

            <style>
            @import url('https://rsms.me/inter/inter.css');
            :root {
                --tblr-font-sans-serif: 'Inter Var', -apple-system, BlinkMacSystemFont, San Francisco, Segoe UI, Roboto, Helvetica Neue, sans-serif;
            }
            body {
                font-feature-settings: "cv03", "cv04", "cv11";
            }
            </style>
        </head>
        <body  class=" d-flex flex-column" data-bs-theme="<?php echo $getTheme;?>">
            <div class="page page-center">
            <div class="container container-tight py-4">
                <div class="text-center mb-4">
                <a href="." class="navbar-brand navbar-brand-autodark"><img src="<?php print_external('logo');?>" height="36" alt=""></a>
                </div>
                <div class="card card-md">
                <div class="card-body">
                    <!-- <h2 class="h2 text-center mb-4">Login to your account</h2> -->
                    <form action="" method="post" autocomplete="off" novalidate>
                    <div class="mb-3">
                        <label class="form-label"><?php echo lng('Username'); ?></label>
                        <input type="email" name='f_name' class="form-control" placeholder="<?php echo lng('Username'); ?>" autocomplete="off">
                    </div>
                    <div class="mb-2">
                        <label class="form-label">
                            <?php echo lng('Password'); ?>
                        </label>
                        <div class="input-group input-group-flat">
                        <input type="password" name='f_password' class="form-control"  placeholder="<?php echo lng('Password'); ?>"  autocomplete="off">
                        <span class="input-group-text">
                            <a href="#" class="link-secondary" title="Show password" data-bs-toggle="tooltip">
                            <svg xmlns="<?php print_external('icon-2000');?>" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M10 12a2 2 0 1 0 4 0a2 2 0 0 0 -4 0" /><path d="M21 12c-2.4 4 -5.4 6 -9 6c-3.6 0 -6.6 -2 -9 -6c2.4 -4 5.4 -6 9 -6c3.6 0 6.6 2 9 6" /></svg>
                            </a>
                        </span>
                        </div>
                    </div>
                    <div class="form-footer">
                        <input type="hidden" name="token" value="<?php echo htmlentities($_SESSION['token']); ?>" />
                        <button type="submit" class="btn btn-primary w-100"><?php echo lng('Login'); ?></button>
                    </div>
                    </form>
                </div>
                </div>
            </div>
            </div>
            <!-- Libs JS -->
            <!-- Tabler Core -->
            <?php print_external('js-tabler');?>
            <?php print_external('js');?>
        </body>
        </html>

    <?php
        //登录界面结束
        exit;
    }
}

$html_path="";//前端页面显示的路径

if ($use_auth || isset($_SESSION[FM_SESSION_ID]['logged'])) {
    //登录状态下
    if (isset($_SESSION[FM_SESSION_ID]['path'])) {
        $root_path = !empty($_SESSION[FM_SESSION_ID]['path']) ? $_SESSION[FM_SESSION_ID]['path'] : $root_path;
        $html_path = !empty($_SESSION[FM_SESSION_ID]['path']) ? $_SESSION[FM_SESSION_ID]['path'] : $html_path;
    }
}
    $root_path = rtrim($root_path, '\\/');
    $root_path = str_replace('\\', '/', $root_path);
    if (!@is_dir($root_path)) {
        echo "<h1>" . lng('Root path') . " \"{$root_path}\" " . lng('not found!') . " </h1>";
        exit;
    }

    defined('FM_SHOW_HIDDEN') || define('FM_SHOW_HIDDEN', $show_hidden_files);
    defined('FM_ROOT_PATH') || define('FM_ROOT_PATH', $root_path);
    defined('FM_LANG') || define('FM_LANG', $lang);
    defined('FM_FILE_EXTENSION') || define('FM_FILE_EXTENSION', $allowed_file_extensions);
    defined('FM_UPLOAD_EXTENSION') || define('FM_UPLOAD_EXTENSION', $allowed_upload_extensions);
    defined('FM_EXCLUDE_ITEMS') || define('FM_EXCLUDE_ITEMS', (version_compare(PHP_VERSION, '7.0.0', '<') ? serialize($exclude_items) : $exclude_items));
    defined('FM_DOC_VIEWER') || define('FM_DOC_VIEWER', $online_viewer);
    define('FM_READONLY', $global_readonly || ($use_auth && !empty($readonly_users) && isset($_SESSION[FM_SESSION_ID]['logged']) && in_array($_SESSION[FM_SESSION_ID]['logged'], $readonly_users)));
    define('FM_IS_WIN', DIRECTORY_SEPARATOR == '\\');

    // always use ?p=
    if ((!isset($_GET['p']) && !isset($_GET['nav'])) && empty($_FILES)) {
        fm_redirect(FM_SELF_URL . '?p=');
    }

    // get path
    $p = isset($_GET['p']) ? $_GET['p'] : (isset($_POST['p']) ? $_POST['p'] : '');

    // clean path
    $p = fm_clean_path($p);

    // for ajax request - save
    $input = file_get_contents('php://input');
    $_POST = (strpos($input, 'ajax') != false && strpos($input, 'save') != false) ? json_decode($input, true) : $_POST;

    // instead globals vars
    define('FM_PATH', $p);
    define('FM_USE_AUTH', $use_auth);
    define('FM_EDIT_FILE', $edit_files);
    defined('FM_ICONV_INPUT_ENC') || define('FM_ICONV_INPUT_ENC', $iconv_input_encoding);
    defined('FM_USE_HIGHLIGHTJS') || define('FM_USE_HIGHLIGHTJS', $use_highlightjs);
    defined('FM_HIGHLIGHTJS_STYLE') || define('FM_HIGHLIGHTJS_STYLE', $highlightjs_style);
    defined('FM_DATETIME_FORMAT') || define('FM_DATETIME_FORMAT', $datetime_format);

    unset($p, $use_auth, $iconv_input_encoding, $use_highlightjs, $highlightjs_style);

    //用户相关的表单提交
    if(isset($_GET['nav']) && $_GET['nav']=='users'){
        //添加  修改
        if(isset($_POST['name'],$_POST['password'],$_POST['token']) && !FM_READONLY){
            if($_POST['name']=='' && ( $_POST['password']=='' && $_POST['user_hash']=='')){
                $response = array(
                    'status' => 'alert',
                    'info' =>lng('User account and password must be filled in')
                );
                echo json_encode($response);
                exit();
            }

            if(isset($_POST['user_hash']) && !empty($_POST['user_hash'])){
                $user_stmt = $pdo->prepare("SELECT * FROM users WHERE hash = ?");
                $user_stmt->execute([$_POST['user_hash']]);
                $userinfo = $user_stmt->fetch(PDO::FETCH_ASSOC);
                //账号和邮箱已经存在
                $stmt = $pdo->prepare("SELECT * FROM users WHERE name = ? and hash !=?");
                $stmt->execute([$_POST['name'],$_POST['user_hash']]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                if($user){
                    $response = array(
                        'status' => 'alert',
                        'info' =>lng('Username').' '.lng('already exists')
                    );
                    echo json_encode($response);
                    exit();
                }

                if($_POST['email']!=''){
                    $stmt1 = $pdo->prepare("SELECT * FROM users WHERE email = ? and hash !=?");
                    $stmt1->execute([$_POST['email'],$_POST['user_hash']]);
                    $user_e = $stmt1->fetch(PDO::FETCH_ASSOC);
                    if($user_e){
                        $response = array(
                            'status' => 'alert',
                            'info' =>lng('Email').' '.lng('already exists')
                        );
                        echo json_encode($response);
                        exit();
                    }
                }

                if(!empty($_POST['password'])){
                    $password_stmt = $pdo->prepare("UPDATE users SET password=?  WHERE hash = ? ");
                    $hashedPassword = md5($hash.$_POST['password']);
                    $password_stmt->execute([$hashedPassword, $_POST['user_hash']]);
                }

                $update_stmt = $pdo->prepare("UPDATE users SET name=?,email=?,type=?,delete_perm=?,update_time=?  WHERE hash = ? ");
                $update_time=date('Y-m-d H:i:s');
                $update_stmt->execute([$_POST['name'],$_POST['email'],$_POST['type'],$_POST['delete_perm'],$update_time, $_POST['user_hash']]);

                $response = array(
                    'status' => 'success',
                    'info' =>lng('Edit').' '.lng('Success')
                );
            }else{
                //账号和邮箱已经存在
                $stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");
                $stmt->execute([$_POST['name']]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                if($user){
                    $response = array(
                        'status' => 'alert',
                        'info' =>lng('Username').' '.lng('already exists')
                    );
                    echo json_encode($response);
                    exit();
                }

                if($_POST['email']!=''){
                    $stmt1 = $pdo->prepare("SELECT * FROM users WHERE email = ?");
                    $stmt1->execute([$_POST['email']]);
                    $user_e = $stmt1->fetch(PDO::FETCH_ASSOC);
                    if($user_e){
                        $response = array(
                            'status' => 'alert',
                            'info' =>lng('Email').' '.lng('already exists')
                        );
                        echo json_encode($response);
                        exit();
                    }
                }
                $directory=$_POST['path']!=''?$_POST['path']:$_POST['name'];

                $userinfo=registerUser($pdo,$_POST['name'],$_POST['password'],$directory,$_POST['email'],$_POST['type'],$_POST['delete_perm']);
                if(isset($userinfo['hash'])){
                    $directory=str_replace( '/', '', fm_clean_path( strip_tags( $directory ) ) );
                    
                    if (!is_dir($directory)){
                        mkdir($directory, 0777, true);
                        //添加数据入库
                        addFile($pdo,$userinfo['hash'],$directory, 'folder');
                    }
                    $response = array(
                        'status' => 'success',
                        'info' =>lng('CreateNow').' '.lng('Success')
                    );
                }else{
                    $response = array(
                        'status' => 'error',
                        'info' =>lng('CreateNow').' '.lng('Error')
                    );
                }
            }

            echo json_encode($response);
                exit();
        }

        //删除
        if (isset($_GET['del'], $_POST['token']) && !FM_READONLY) {
            $path = FM_ROOT_PATH;
            if (FM_PATH != '') {
                $path .= '/' . FM_PATH;
            }

            $hash=$_GET['del'];
            $stmt = $pdo->prepare("SELECT * FROM users WHERE hash = ?");
            $stmt->execute([$hash]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if($user){
                $flagstatus=isset($_POST['confirm'])?$_POST['confirm']:0;
                if($flagstatus==1){
                    fm_rdelete($path . '/' . $user['path']);
                }
                deleteUser($pdo,$user['hash'],$flagstatus);
                $response = array(
                    'status' => 'success',
                    'info' =>lng('Delete').' '.lng('Success')
                );
            }else{
                $response = array(
                    'status' => 'alert',
                    'info' =>lng('CreateNow').' '.lng('Error')
                );
            }
            echo json_encode($response);
            exit();
        }

        //详情
        if(isset($_GET['detail']) && !FM_READONLY){
            $hash=$_GET['detail'];
            $stmt = $pdo->prepare("SELECT * FROM users WHERE hash = ?");
            $stmt->execute([$hash]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if(!empty($user) && !is_null($user)){
                $response = array(
                    'status' => 'success',
                    'info' =>$user
                );
            }else{
                $response = array(
                    'status' => 'error',
                    'info' =>lng('not found!')
                );
            }
            echo json_encode($response);
            exit();
        }
    }

    //密码修改
    if(isset($_POST['password'], $_POST['token']) && !FM_READONLY){
        $stmt_s = $pdo->prepare("SELECT * FROM users WHERE hash = ?");
        $stmt_s->execute([$_SESSION[FM_SESSION_ID]['hash']]);
        $userinfo = $stmt_s->fetch(PDO::FETCH_ASSOC);
        if(!$userinfo){
            $response = array(
                'status' => 'error',
                'info' =>lng('not found!')
            );
            echo json_encode($response);
            exit();
        }
        $password=md5($userinfo['hash'].$_POST['password']);
        $date=date('Y-m-d H:i:s');
        $stmt = $pdo->prepare("UPDATE users SET password=?,update_time=? WHERE hash = ?");
        $stmt->execute([$password,$date,$_SESSION[FM_SESSION_ID]['hash']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        $response = array(
            'status' => 'success',
            'info' =>lng('Success')
        );
        if($_SESSION[FM_SESSION_ID]['is_first']==1){
            if($_POST['password']!='changeme'){
                $_SESSION[FM_SESSION_ID]['is_first']=0;
            }
        }
        echo json_encode($response);
        exit();
    }

    // Upload
    if (!empty($_FILES)) {
        if (isset($_POST['token'])) {
            if (!verifyToken($_POST['token'])) {
                $response = array('status' => 'error', 'info' => "Invalid Token.");
                echo json_encode($response);exit();
            }
        } else {
            $response = array('status' => 'error', 'info' => "Token Missing.");
            echo json_encode($response);exit();
        }

        $dzuuid=isset($_POST['dzuuid'])?$_POST['dzuuid']:0;//分片id
        $chunkIndex = isset($_POST['dzchunkindex'])?$_POST['dzchunkindex']:0;
        $chunkTotal = isset($_POST['dztotalchunkcount'])?$_POST['dztotalchunkcount']:1;
        $fullPathInput = fm_clean_path($_REQUEST['fullpath']);
        $dzuuids=[];
        if($dzuuid!=0){
            if(!isset($_SESSION[FM_SESSION_ID]['dzuuids'])){
                $_SESSION[FM_SESSION_ID]['dzuuids']=[];
            }else{
                $dzuuids=$_SESSION[FM_SESSION_ID]['dzuuids'];
            }
        }
        
        $f = $_FILES;
        
        $ds = DIRECTORY_SEPARATOR;
        $path = FM_ROOT_PATH;
        $sj_path = $html_path;//FM_ROOT_PATH;
        if (FM_PATH != '') {
            $path .= '/' . FM_PATH;
            
            if(!empty($sj_path))
            {
                $sj_path.='/' ; 
            }
            $sj_path.= FM_PATH;
        }

        $errors = 0;
        $uploads = 0;
        $allowed = (FM_UPLOAD_EXTENSION) ? explode(',', FM_UPLOAD_EXTENSION) : false;

        $response = array(
            'status' => 'error',
            'info' => 'Oops! Try again',
        );

        $filename = $f['file']['name'];
        $tmp_name = $f['file']['tmp_name'];

        $ext = pathinfo($filename, PATHINFO_FILENAME) != '' ? strtolower(pathinfo($filename, PATHINFO_EXTENSION)) : '';

        $filesize = isset($_POST['dztotalfilesize'])?$_POST['dztotalfilesize']:fm_get_size($tmp_name);

        $isFileAllowed = ($allowed) ? in_array($ext, $allowed) : true;
        
        //文件名称
        /* $fullPathInput=$filename; */

        if (!fm_isvalid_filename($filename) && !fm_isvalid_filename($fullPathInput)) {
            $response = array(
                'status' => 'error',
                'info' => "Invalid File name!",
            );
            echo json_encode($response);exit();
        }

        $targetPath = $path . $ds;
        if (is_writable($targetPath)) {
            $fullPath = $path . '/' . $fullPathInput;//basename($fullPathInput)
            $folder = substr($fullPath, 0, strrpos($fullPath, "/"));

            if (!is_dir($folder)) {
                $old = umask(0);
                mkdir($folder, 0777, true);
                umask($old);
            }

            if (empty($f['file']['error']) && !empty($tmp_name) && $tmp_name != 'none' && $isFileAllowed) {
                if ($chunkTotal) {
                    $out = @fopen("{$fullPath}.part", $chunkIndex == 0 ? "wb" : "ab");
                    if ($out) {
                        $in = @fopen($tmp_name, "rb");
                        if ($in) {
                            if (PHP_VERSION_ID < 80009) {
                                // workaround https://bugs.php.net/bug.php?id=81145
                                do {
                                    for (;;) {
                                        $buff = fread($in, 4096);
                                        if ($buff === false || $buff === '') {
                                            break;
                                        }
                                        fwrite($out, $buff);
                                    }
                                } while (!feof($in));
                            } else {
                                stream_copy_to_stream($in, $out);
                            }
                            $response = array(
                                'status' => 'success',
                                'info' => "file upload successful",
                            );
                        } else {
                            $response = array(
                                'status' => 'error',
                                'info' => "failed to open output stream",
                                'errorDetails' => error_get_last(),
                            );
                        }
                        @fclose($in);
                        @fclose($out);
                        @unlink($tmp_name);

                        $response = array(
                            'status' => 'success',
                            'info' => "file upload successful ",
                        );
                    } else {
                        $response = array(
                            'status' => 'error',
                            'info' => "failed to open output stream",
                        );
                    }

                    if ($chunkIndex == $chunkTotal - 1) {
                        if (file_exists($fullPath)) {
                            $ext_1 = $ext ? '.' . $ext : '';
                            $d=date('ymdHis');
                            $fullPathTarget = $path . '/' . basename($fullPathInput, $ext_1) . '_' . $d . $ext_1;
                            $filename_l=basename($fullPathInput, $ext_1) . '_' . $d . $ext_1;
                        } else {
                            $fullPathTarget = $fullPath;
                        }
                        rename("{$fullPath}.part", $fullPathTarget);
                    }

                } else if (move_uploaded_file($tmp_name, $fullPath)) {
                    // Be sure that the file has been uploaded
                    if (file_exists($fullPath)) {
                        $response = array(
                            'status' => 'success',
                            'info' => "file upload successful",
                        );
                    } else {
                        $response = array(
                            'status' => 'error',
                            'info' => 'Couldn\'t upload the requested file.',
                        );
                    }
                } else {
                    $response = array(
                        'status' => 'error',
                        'info' => "Error while uploading files. Uploaded files $uploads",
                    );
                }
            }
        } else {
            $response = array(
                'status' => 'error',
                'info' => 'The specified folder for upload isn\'t writeable.',
            );
        }

        if($response['status']=='success'){
            
            if($dzuuid==0 || !in_array($dzuuid,$dzuuids)){
                if($dzuuid!=0){
                    array_push($dzuuids,$dzuuid);
                    $_SESSION[FM_SESSION_ID]['dzuuids']=$dzuuids;
                }
                $f_name=isset($filename_l)?$filename_l:$filename;
                addFile($pdo,$_SESSION[FM_SESSION_ID]['hash'],$f_name, 'file',$sj_path,$filesize,$ext);
            }
        }
        // Return the response
        echo json_encode($response);
        exit();
    }

    // Delete file / folder
    if (isset($_GET['del'], $_POST['token']) && !FM_READONLY) {
        $del = str_replace( '/', '', fm_clean_path( $_GET['del'] ) );
        if ($del != '' && $del != '..' && $del != '.' && verifyToken($_POST['token'])) {
            $path = FM_ROOT_PATH;
            $sj_path = $html_path;//FM_ROOT_PATH;
            if (FM_PATH != '') {
                $path .= '/' . FM_PATH;
                
                if(!empty($sj_path))
                {
                    $sj_path.='/' ; 
                }
                $sj_path.= FM_PATH;
            }
            $is_dir = is_dir($path . '/' . $del);

            //查看当前用户删除权限是硬删除还是软删除
            if($_SESSION[FM_SESSION_ID]['user']['delete_perm']==1 || $_SESSION[FM_SESSION_ID]['user']['type']=='admin'){
                //硬删除
                if (fm_rdelete($path . '/' . $del)) {
                    //获取当前删除对象是否文件夹 --文件夹下面的文件一起删除
                    $info=getFile($pdo,$_SESSION[FM_SESSION_ID]['hash'],$del,$sj_path);
                    $msg = $is_dir ? lng('Folder').' <b>%s</b> '.lng('Deleted') : lng('File').' <b>%s</b> '.lng('Deleted');
    
                    if($info || (isset($info['type']) && $info['type']=='folder')){
                        //整个目录下的数据都删除
                        deleteFile($pdo,$_SESSION[FM_SESSION_ID]['hash'],null,$sj_path.'/'.$del.'%');
                    }
                    //数据更新
                    deleteFile($pdo,$_SESSION[FM_SESSION_ID]['hash'],$del,$sj_path);
                    $response = array(
                        'status' => 'success',
                        'info' =>sprintf($msg, fm_enc($del))
                    );
                } else {
                    $msg = $is_dir ? lng('Folder').' <b>%s</b> '.lng('not deleted') : lng('File').' <b>%s</b> '.lng('not deleted');
                    $response = array(
                        'status' => 'error',
                        'info' =>sprintf($msg, fm_enc($del))
                    );
                }
            }else{
                //软删除 --标记数据状态为-1
                //获取当前删除对象是否文件夹 --文件夹下面的文件一起删除
                $info=getFile($pdo,$_SESSION[FM_SESSION_ID]['hash'],$del,$sj_path);

                if($info){
                    if(isset($info['type']) && $info['type']=='folder'){
                        //整个目录下的数据都删除
                        updateStatusFolder($pdo,$_SESSION[FM_SESSION_ID]['hash'],$info['hash'],0);
                    }
                    //数据更新
                    updateStatusFolder($pdo,$_SESSION[FM_SESSION_ID]['hash'],$info['hash'],0); 
                }

                $msg = $is_dir ? lng('Folder').' <b>%s</b> '.lng('Deleted') : lng('File').' <b>%s</b> '.lng('Deleted');
                $response = array(
                    'status' => 'success',
                    'info' =>sprintf($msg, fm_enc($del))
                );
            }
        } else {
            $response = array(
                'status' => 'error',
                'info' =>lng('Invalid file or folder name')
            );
        }
        echo json_encode($response);
        exit();
    }

    // Create a new folder
    if (isset($_POST['newfilename'], $_POST['token'])) {
        $new = str_replace( '/', '', fm_clean_path( strip_tags( $_POST['newfilename'] ) ) );
        if (fm_isvalid_filename($new) && $new != '' && $new != '..' && $new != '.' && verifyToken($_POST['token'])) {
            $path = FM_ROOT_PATH;
            $sj_path = $html_path;//FM_ROOT_PATH;
            if (FM_PATH != '') {
                $path .= '/' . FM_PATH;

                if(!empty($sj_path))
                {
                    $sj_path.='/' ; 
                }
                $sj_path.= FM_PATH;
            }
            
            if (fm_mkdir($path . '/' . $new, false) === true) {
                //数据入库
                addFile($pdo,$_SESSION[FM_SESSION_ID]['hash'],$new, 'folder',$sj_path);
                $response = array(
                    'status' => 'success',
                    'info' =>sprintf(lng('Folder').' <b>%s</b> '.lng('Created'), $new)
                );
            } elseif (fm_mkdir($path . '/' . $new, false) === $path . '/' . $new) {
                $response = array(
                    'status' => 'alert',
                    'info' =>sprintf(lng('Folder').' <b>%s</b> '.lng('already exists'), fm_enc($new))
                );
            } else {
                $response = array(
                    'status' => 'error',
                    'info' =>sprintf(lng('Folder').' <b>%s</b> '.lng('not created'), fm_enc($new))
                );
            }
        } else {
            $response = array(
                'status' => 'error',
                'info' =>lng('Invalid characters in file or folder name')
            );
        }
        echo json_encode($response);
        exit();
    }

    // Rename
    if (isset($_POST['rename_from'], $_POST['rename_to'], $_POST['token']) && !FM_READONLY) {
        if(!verifyToken($_POST['token'])) {
            $response = array(
                'status' => 'error',
                'info' =>"Invalid Token."
            );
            echo json_encode($response);
            exit();
        }
        // old name
        $old = urldecode($_POST['rename_from']);
        $old = fm_clean_path($old);
        $old = str_replace('/', '', $old);
        // new name
        $new = urldecode($_POST['rename_to']);
        $new = fm_clean_path(strip_tags($new));
        $new = str_replace('/', '', $new);
        // path
        $path = FM_ROOT_PATH;
        $sj_path = $html_path;//FM_ROOT_PATH;
        if (FM_PATH != '') {
            $path .= '/' . FM_PATH;
            
            if(!empty($sj_path))
            {
                $sj_path.='/' ; 
            }
            $sj_path.= FM_PATH;
        }
        // rename
        if (fm_isvalid_filename($new) && $old != '' && $new != '') {
            if (fm_rename($path . '/' . $old, $path . '/' . $new)) {
                //数据更新
                updateFile($pdo,$_SESSION[FM_SESSION_ID]['hash'],$old,$new,$sj_path);
                $response = array(
                    'status' => 'success',
                    'info' =>sprintf(lng('Renamed from').' <b>%s</b> '. lng('to').' <b>%s</b>', fm_enc($old), fm_enc($new))
                );
            } else {
                $response = array(
                    'status' => 'error',
                    'info' =>sprintf(lng('Error while renaming from').' <b>%s</b> '. lng('to').' <b>%s</b>', fm_enc($old), fm_enc($new))
                );
            }
        } else {
            $response = array(
                'status' => 'error',
                'info' =>lng('Invalid characters in file name')
            );
        }
        echo json_encode($response);
        exit();
    }

    // Download
    if (isset($_GET['dl'], $_POST['token'])) {
        if(!verifyToken($_POST['token'])) {
            fm_set_msg("Invalid Token.", 'error');
        }

        $dl = urldecode($_GET['dl']);
        $dl = fm_clean_path($dl);
        $dl = str_replace('/', '', $dl);
        $path = FM_ROOT_PATH;
        if (FM_PATH != '') {
            $path .= '/' . FM_PATH;
        }
        if ($dl != '' && is_file($path . '/' . $dl)) {
            fm_download_file($path . '/' . $dl, $dl, 1024);
            exit;
        } else {
            fm_set_msg(lng('File not found'), 'error');
            $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
        }
    }

    // 批量 deleting
    if (isset($_POST['group'], $_POST['delete'], $_POST['token']) && !FM_READONLY) {
        if(!verifyToken($_POST['token'])) {
            $response = array(
                'status' => 'error',
                'info' =>lng("Invalid Token.")
            );
            echo json_encode($response);
            exit;
        }

        $path = FM_ROOT_PATH;
        $sj_path = $html_path;//FM_ROOT_PATH;
        if (FM_PATH != '') {
            $path .= '/' . FM_PATH;
            
            if(!empty($sj_path))
            {
                $sj_path.='/' ; 
            }
            $sj_path.= FM_PATH;
        }

        $errors = 0;
        $files = $_POST['file'];
        $files=json_decode($files);
        if (is_array($files) && count($files)) {
            foreach ($files as $finfo) {
                $f=$finfo->id;
                if ($f != '') {
                    $new_path = $path . '/' . $f;
                     //查看当前用户删除权限是硬删除还是软删除
                    if($_SESSION[FM_SESSION_ID]['user']['delete_perm']==1 || $_SESSION[FM_SESSION_ID]['user']['type']=='admin'){
                        if (!fm_rdelete($new_path)) {
                            $errors++;
                        }else{
                            //获取当前删除对象是否文件夹 --文件夹下面的文件一起删除
                            $info=getFile($pdo,$_SESSION[FM_SESSION_ID]['hash'],$f,$path);
                            if($info || (isset($info['type']) && $info['type']=='folder')){
                                //整个目录下的数据都删除
                                deleteFile($pdo,$_SESSION[FM_SESSION_ID]['hash'],null,$path.'/'.$f.'%');
                            }
                            //数据更新
                            deleteFile($pdo,$_SESSION[FM_SESSION_ID]['hash'],$f,$path);
                        }
                    }else{
                        //软删除 --标记数据状态为-1
                        //获取当前删除对象是否文件夹 --文件夹下面的文件一起删除
                        $info=getFile($pdo,$_SESSION[FM_SESSION_ID]['hash'],$del,$sj_path);

                        if($info || (isset($info['type']) && $info['type']=='folder')){
                            //整个目录下的数据都删除
                            updateStatusFolder($pdo,$_SESSION[FM_SESSION_ID]['hash'],$info['hash'],0);
                        }
                        //数据更新
                        updateStatusFolder($pdo,$_SESSION[FM_SESSION_ID]['hash'],$info['hash'],0);
                    }
                }
            }
            if ($errors == 0) {
                $response = array(
                    'status' => 'success',
                    'info' =>lng('Selected files and folder deleted')
                );
            } else {
                $response = array(
                    'status' => 'error',
                    'info' =>lng('Error while deleting items')
                );
            }
        } else {
            $response = array(
                'status' => 'alert',
                'info' =>lng('Nothing selected')
            );
        }
        echo json_encode($response);
        exit;
    }

    // 文件打包 zip, tar
    if (isset($_POST['group'], $_POST['token']) && (isset($_POST['zip']) || isset($_POST['tar'])) && !FM_READONLY) {
        if(!verifyToken($_POST['token'])) {
            $response = array(
                'status' => 'error',
                'info' =>lng("Invalid Token.")
            );
            echo json_encode($response);
            exit();
        }

        $path = FM_ROOT_PATH;
        $sj_path = $html_path;//FM_ROOT_PATH;
        if (FM_PATH != '') {
            $path .= '/' . FM_PATH;
            
            if(!empty($sj_path))
            {
                $sj_path.='/' ; 
            }
            $sj_path.= FM_PATH;
        }
        $ext = 'zip';

        //set 打包 type
        $ext = isset($_POST['type']) ? $_POST['type'] : 'zip';

        if (($ext == "zip" && !class_exists('ZipArchive')) || ($ext == "tar" && !class_exists('PharData'))) {
            $response = array(
                'status' => 'error',
                'info' =>lng('Operations with archives are not available')
            );
            echo json_encode($response);
            exit();
        }

        $files = $_POST['file'];
        if(empty($files)){
            $response = array(
                'status' => 'alert',
                'info' =>lng('Nothing selected')
            );
            echo json_encode($response);
            exit();
        }
        
        $sanitized_files = array();

        // clean path
        $files_arr=json_decode($files);
        
        foreach($files_arr as $file){
            array_push($sanitized_files, fm_clean_path($file->id));
        }
        
        $files = $sanitized_files;
        
        if (!empty($files)) {
            chdir($path);

            if(isset($_POST['packname']) && !empty($_POST['packname'])){
                //手动填写的打包文件名
                $zipname=basename($_POST['packname']). '.'.$ext;
                $fullfile=$path.'/'.$zipname;
                if(file_exists($fullfile)){
                    $d=date('ymdHis');
                    $zipname=basename($_POST['packname']).'='.$d. '.'.$ext;
                }
            }else{
                if (count($files) == 1) {
                    $one_file = reset($files);
                    $one_file = basename($one_file);
                    $zipname = $one_file . '_' . date('ymd_His') . '.'.$ext;
                } else {
                    $zipname = 'archive_' . date('ymd_His') . '.'.$ext;
                }
            }

            if($ext == 'zip') {
                $zipper = new FM_Zipper();
                $res = $zipper->create($zipname, $files);
            } elseif ($ext == 'tar') {
                $tar = new FM_Zipper_Tar();
                $res = $tar->create($zipname, $files);
            }

            if ($res) {
                //数据入库
                $filesize = fm_get_size($path.'/'.$zipname);
                
                addFile($pdo,$_SESSION[FM_SESSION_ID]['hash'],$zipname,'file',$sj_path,$filesize,$ext);
                $response = array(
                    'status' => 'success',
                    'info' =>sprintf(lng('Archive').' <b>%s</b> '.lng('Created'), fm_enc($zipname))
                );
            } else {
                $response = array(
                    'status' => 'error',
                    'info' =>lng('Archive not created')
                );
            }
        } else {
            $response = array(
                'status' => 'alert',
                'info' =>lng('Nothing selected')
            );
        }
        echo json_encode($response);
        exit();
    }

    // Unpack zip, tar
    if (isset($_POST['unzip'], $_POST['token']) && !FM_READONLY) {
        if(!verifyToken($_POST['token'])) {
            $response = array(
                'status' => 'error',
                'info' =>lng("Invalid Token.")
            );
            echo json_encode($response);
            exit();
        }

        $unzip = urldecode($_POST['unzip']);
        $unzip = fm_clean_path($unzip);
        $unzip = str_replace('/', '', $unzip);

        $isValid = false;

        $path = FM_ROOT_PATH;
        $sj_path = $html_path;//FM_ROOT_PATH;
        if (FM_PATH != '') {
            $path .= '/' . FM_PATH;
            if(!empty($sj_path)){
                $sj_path.='/' ;
            }
            $sj_path.= FM_PATH;
        }

        if ($unzip != '' && is_file($path . '/' . $unzip)) {
            $zip_path = $path . '/' . $unzip;
            $ext = pathinfo($zip_path, PATHINFO_EXTENSION);
            $isValid = true;
        } else {
            $response = array(
                'status' => 'error',
                'info' =>lng('File not found')
            );
            echo json_encode($response);
            exit();
        }

        if (($ext == "zip" && !class_exists('ZipArchive')) || ($ext == "tar" && !class_exists('PharData'))) {
            $response = array(
                'status' => 'error',
                'info' =>lng('Operations with archives are not available')
            );
            echo json_encode($response);
            exit();
        }

        if ($isValid) {
            //to folder
            if (isset($_POST['tofolder']) && $_POST['tofolder']!='') {
                if (fm_mkdir($path . '/' . $_POST['tofolder'], true)) {
                    $path .= '/' . $_POST['tofolder'];
                    $sj_path.='/' . $_POST['tofolder'];

                    $tofolder_arr=explode('/',$_POST['tofolder']);
                    //目录数据添加
                    $folder_folder_path=$sj_path;
                    foreach($tofolder_arr as $tofolder_info){
                        addFile($pdo,$_SESSION[FM_SESSION_ID]['hash'],$tofolder_info,'folder',$folder_folder_path,'','');
                        $folder_folder_path.='/'.$tofolder_info;
                    }
                }
            }
            
            if($ext == "zip") {
                $zipper = new FM_Zipper();
                $res = $zipper->unzip($zip_path, $path);
            } elseif ($ext == "tar") {
                try {
                    $gzipper = new PharData($zip_path);
                    if (@$gzipper->extractTo($path,null, true)) {
                        $res = true;
                    } else {
                        $res = false;
                    }
                } catch (Exception $e) {
                    //TODO:: need to handle the error
                    $res = true;
                }
            }

            if ($res) {
                $list=fm_get_zif_info($zip_path,$ext);
                if(!empty($list)){
                    //文件数据入库
                    foreach($list as $item){
                        $name_arr=explode('/',$item['name']);
                        $name=end($name_arr);
                        $type='file';
                        if($item['folder']==1){
                            $name=prev($name_arr);
                            $type='folder';
                        }else{
                            foreach($name_arr as $n_item){
                                if(!empty($n_item) && $n_item!=$name){
                                    $sj_path.='/'.$n_item;
                                }
                            }
                        }
                        $zip_file_info=getFile_u($pdo,$name,$sj_path);
                        if(empty($zip_file_info) || is_null($zip_file_info)){
                            //不存在 添加数据
                            $fileinfo_ext_arr=explode('.',$name);
                            $fileinfo_ext=end($fileinfo_ext_arr);
                            addFile($pdo,$_SESSION[FM_SESSION_ID]['hash'],$name,$type,$sj_path,$item['filesize'],$fileinfo_ext);
                        }
                    }
                }
                
                $response = array(
                    'status' => 'success',
                    'info' =>lng('Archive unpacked')
                );
            } else {
                $response = array(
                    'status' => 'error',
                    'info' =>lng('Archive not unpacked')
                );
            }
        } else {
            $response = array(
                'status' => 'error',
                'info' =>lng('File not found')
            );
        }
        echo json_encode($response);
        exit();
    }

    //获取文件详情
    if(isset($_GET['detail'])){
        $file = $_GET['detail'];
        $file = fm_clean_path($file, false);
        $file = str_replace('/', '', $file);

        // path
        $path = FM_ROOT_PATH;
        if (FM_PATH != '') {
            $path .= '/' . FM_PATH;
        }

        if ($file == '' || !is_file($path . '/' . $file) || !fm_is_exclude_items($file)) {
            $response=[
                'status' => 'error',
                'info'=>lng('File not found'),
            ];
            echo json_encode($response);
            exit;
        }

        $file_url = FM_ROOT_URL .(!empty($html_path)?'/'.$html_path:'' ). fm_convert_win((FM_PATH != '' ? '/' . FM_PATH : '') . '/' . $file);
        $file_path = $path . '/' . $file;

        $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        $mime_type = fm_get_mime_type($file_path);
        $filesize_raw = fm_get_size($file_path);
        $filesize = fm_get_filesize($filesize_raw);

        $modif_raw = filemtime($file_path);
        $modif = date(FM_DATETIME_FORMAT, $modif_raw);

        $is_zip = false;
        $is_gzip = false;
        $is_image = false;
        $is_audio = false;
        $is_video = false;
        $is_text = false;
        $is_onlineViewer = false;

        $view_title = 'File';
        $filenames = false; // for zip
        $content = ''; // for text
        $online_viewer = strtolower(FM_DOC_VIEWER);

        if($online_viewer && $online_viewer !== 'false' && in_array($ext, fm_get_onlineViewer_exts())){
            $is_onlineViewer = true;
        }
        elseif ($ext == 'zip' || $ext == 'tar') {
            $is_zip = true;
            $view_title = 'Archive';
            $filenames = fm_get_zif_info($file_path, $ext);
        } elseif (in_array($ext, fm_get_image_exts())) {
            $is_image = true;
            $view_title = 'Image';
        } elseif (in_array($ext, fm_get_audio_exts())) {
            $is_audio = true;
            $view_title = 'Audio';
        } elseif (in_array($ext, fm_get_video_exts())) {
            $is_video = true;
            $view_title = 'Video';
        } elseif (in_array($ext, fm_get_text_exts()) || substr($mime_type, 0, 4) == 'text' || in_array($mime_type, fm_get_text_mimes())) {
            $is_text = true;
            $content = file_get_contents($file_path);
        }

        $html='';
        // ZIP info
        if($is_onlineViewer) {
            //现在本地文件线上不能访问 测试https://console.unifyestate.com/apartment-v2.7.xlsx
            //$file_url='https://filebuckets.com/Proposal%20-%20VIC%20-%2017%20Wordsworth%20Ave.pdf';
            if($online_viewer == 'google') {
                $html.= '<iframe src="https://docs.google.com/viewer?embedded=true&hl=en&url=' . fm_enc($file_url) . '" frameborder="no" style="width:100%;min-height:460px"></iframe>';
            } else if($online_viewer == 'microsoft') {
                $html.= '<iframe src="https://view.officeapps.live.com/op/embed.aspx?src=' . fm_enc($file_url) . '" frameborder="no" style="width:100%;min-height:460px"></iframe>';
            }
        }elseif (($is_zip || $is_gzip) && $filenames !== false) {
            $html.= '<code class="maxheight">';
            foreach ($filenames as $fn) {
                if ($fn['folder']) {
                    $html.=  '<b>' . fm_enc($fn['name']) . '</b><br>';
                } else {
                    $html.=  $fn['name'] . ' (' . fm_get_filesize($fn['filesize']) . ')<br>';
                }
            }
            $html.=  '</code>';
        }elseif($is_image){
            if (in_array($ext, array('gif', 'jpg', 'jpeg', 'png', 'bmp', 'ico', 'svg', 'webp', 'avif'))) {
                $html.= '<p><img src="' . fm_enc($file_url) . '" alt="image"></p>';
            }
        }elseif ($is_audio) {
            // Audio content
            $html.='<p><audio src="' . fm_enc($file_url) . '" controls preload="metadata"></audio></p>';
        } elseif ($is_video) {
            // Video content
            $html.='<div class="preview-video"><video id="myVideo" src="' . fm_enc($file_url) . '" width="640" height="360" controls preload="metadata"></video></div>';
        }elseif ($is_text) {
            if (FM_USE_HIGHLIGHTJS) {
                // highlight
                $hljs_classes = array(
                    'shtml' => 'xml',
                    'htaccess' => 'apache',
                    'phtml' => 'php',
                    'lock' => 'json',
                    'svg' => 'xml',
                );
                $hljs_class = isset($hljs_classes[$ext]) ? 'lang-' . $hljs_classes[$ext] : 'lang-' . $ext;
                if (empty($ext) || in_array(strtolower($file), fm_get_text_names()) || preg_match('#\.min\.(css|js)$#i', $file)) {
                    $hljs_class = 'nohighlight';
                }
                $html.= '<pre class="with-hljs"><code class="' . $hljs_class . '">' . fm_enc($content) . '</code></pre>';
            } elseif (in_array($ext, array('php', 'php4', 'php5', 'phtml', 'phps'))) {
                // php highlight
                $html.= highlight_string($content, true);
            } else {
                $html.= '<pre>' . fm_enc($content) . '</pre>';
            }
        }
        $response=[
            'status' => 'success',
            'name'=> $file,
            'size'=> $filesize,
            'ext'=> $ext,
            'date'=> $modif,
            'html'=>$html,
        ];
        echo json_encode($response);
        exit;
    }

    //搜索关键词
    if(isset($_POST['type']) && $_POST['type']=="search") {
        $dir = $_POST['path'] == "." ? '': $_POST['path'];
        $response = scan(fm_clean_path($dir), $_POST['content']);
        echo json_encode($response);
        exit();
    }

    //复制或者移动
    if(isset($_POST['copy_to'])){
        //文件本体，有可能是多个文件，数组对象
        $file=$_POST['file'];
        $file_arr=json_decode($file);//多个对象
        
        //类型 1=复制；2=移动
        $copy_type=$_POST['copy_type'];

        // from
        $path = FM_ROOT_PATH;
        if (FM_PATH != '') {
            $path .= '/' . FM_PATH;
        }

        // to 目标文件夹
        $copy_to_path = $path;
        $sj_copy_to_path = $html_path;//FM_ROOT_PATH;
        $copy_to = fm_clean_path($_POST['copy_to']);
        if ($copy_to != '') {
            $copy_to_path .= '/' . $copy_to;
            if(!empty($sj_copy_to_path))
            {
                $sj_copy_to_path.='/' ; 
            }
            $sj_copy_to_path.= $copy_to;
        }


        if ($path == $copy_to_path) {
            //原路径和目标路径一样提醒
            $response = array(
                'status' => 'alert',
                'info' =>lng('Paths must be not equal')
            );
            echo json_encode($response);
            exit();
        }
        if (!is_dir($copy_to_path)) {
            if (!fm_mkdir($copy_to_path, true)) {
                $response = array(
                    'status' => 'error',
                    'info' =>'Unable to create destination folder'
                );
                echo json_encode($response);
                exit();
            }
        }

        //未选择对应文件
        if(empty($file_arr)){
            $response = array(
                'status' => 'alert',
                'info' =>lng('Nothing selected')
            );
            echo json_encode($response);
            exit();
        }

        $errors = 0;
        foreach($file_arr as $finfo) {
            $f=$finfo->id;
            if ($f != '') {
                $f = fm_clean_path($f);
                // abs path from
                $from = $path . '/' . $f;
                // abs path to
                $dest = $copy_to_path . '/' . $f;
                // do

                //数据库中的原数据
                $info=getFile($pdo,$_SESSION[FM_SESSION_ID]['hash'],$f,$path);
                if ($copy_type==2) {
                    //move --转移
                    $rename = fm_rename($from, $dest);
                    if ($rename === false) {
                        $errors++;
                    }else{
                        if($info){
                            //修改对应路径
                            updateFolder($pdo,$_SESSION[FM_SESSION_ID]['hash'],$info['hash'],$sj_copy_to_path);
                        }else{
                            //新增入库
                            addFile($pdo,$_SESSION[FM_SESSION_ID]['hash'],$f,'file',$sj_copy_to_path);
                        }
                    }
                } else {
                    //copy --新增数据
                    if (!fm_rcopy($from, $dest)) {
                        $errors++;
                    }else{
                        //新增入库
                        addFile($pdo,$_SESSION[FM_SESSION_ID]['hash'],$f,'file',$sj_copy_to_path);
                    }
                }
            }
        }

        if($errors==0){
            $msg = $copy_type==1 ? 'Selected files and folders moved' : 'Selected files and folders copied';
            $response = array(
                'status' => 'success',
                'info' =>$msg
            );
        } else {
            $msg = $move ? 'Error while moving items' : 'Error while copying items';
            $response = array(
                'status' => 'error',
                'info' =>$msg
            );
        }

        echo json_encode($response);
        exit();
    }

    //获取文件夹的所有文件夹数据
    if(isset($_GET['folderTree'])){
        
        // path
        $path = FM_ROOT_PATH;
        if (FM_PATH != '') {
            $path .= '/' . FM_PATH;
        }

        $result=get_folders($path);
        print_r($result);
        exit;
    }

    // get current path
    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }

    // check path
    if (!is_dir($path)) {
        fm_redirect(FM_SELF_URL . '?p=');
    }

    // get parent folder
    $parent = fm_get_parent_path(FM_PATH);

    $nav=isset($_GET['nav'])?$_GET['nav']:'home';

    // upload form

    fm_show_header($nav,FM_PATH); // HEADER
    fm_show_nav_path(FM_PATH,$nav); // current path

    // show alert messages
    fm_show_message();
    
    if(isset($_GET['nav'])){
        if($_GET['nav']=='users'){
            if($_SESSION[FM_SESSION_ID]['user']['type']=='admin'){
                //获取用户列表
                $query = "SELECT * FROM users";
                // 执行查询并获取结果集
                $stmt = $pdo->query($query);
                $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
            }else{
                $results=[];
            }

            ?>
            <!-- Page body -->
        <div class="page-body">
          <div class="container-xl">
            <div class="card">
              <div class="card-body">
                <div id="table-default-users" class="table-responsive">
                  <table class="table" id="table-list-users">
                    <thead>
                      <tr>
                        <th><button class="table-sort" data-sort="sort-name"><?php echo lng('Username') ?></button></th>
                        <th><button class="table-sort" data-sort="sort-email"><?php echo lng('Email') ?></button></th>
                        <th><button class="table-sort" data-sort="sort-type"><?php echo lng('UserType') ?></button></th>
                        <th><button class="table-sort" data-sort="sort-status"><?php echo lng('Status') ?></button></th>
                        <th><button class="table-sort" data-sort="sort-date"><?php echo lng('Date') ?></button></th>
                        <th><button class="table-sort" data-sort="sort-operation"><?php echo lng('Operation') ?></button></th>
                      </tr>
                    </thead>
                    <tbody class="table-tbody">
                      <?php
                      foreach ($results as $row){
                      ?>
                      <tr>
                        <td class="sort-name"><?php echo $row['name'];?></td>
                        <td class="sort-email"><?php echo isset($row['email'])?$row['email']:'';?></td>
                        <td class="sort-type"><?php echo isset($row['type'])?$row['type']:'';?></td>
                        <td class="sort-status"></td>
                        <td class="sort-date" data-date="<?php echo isset($row['update_time'])?strtotime($row['update_time']):'';?>"><?php echo isset($row['update_time'])?$row['update_time']:'';?></td>
                        <td class="sort-operation">
                            <div class='btn-list flex-nowrap'>
                                <?php if($row['name']!='admin'){ ?>
                                <a  data-bs-toggle="modal" data-bs-target="#confirmDailog-user-modal" data-title="<?php echo lng('Delete').' '.lng('Users'); ?>" data-name="<?php echo $row['name']?>"  data-url="?nav=users&amp;del=<?php echo urlencode($row['hash']) ?>"  class="btn btn-danger btn-icon btn-icon1" data-action="delete" aria-label="delete">
                                    <svg xmlns="<?php print_external('icon-2000');?>" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-trash"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M4 7l16 0"></path><path d="M10 11l0 6"></path><path d="M14 11l0 6"></path><path d="M5 7l1 12a2 2 0 0 0 2 2h8a2 2 0 0 0 2 -2l1 -12"></path><path d="M9 7v-3a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v3"></path></svg>
                                </a>
                                <?php } ?>

                                <a  onclick="edit('edit','<?php echo lng('Edit').' '.lng('Users'); ?>', '<?php echo $row['hash'] ?>');return false;" class="btn btn-twitter btn-icon btn-icon1" aria-label="edit">
                                    <svg xmlns="<?php print_external('icon-2000');?>" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-edit"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M7 7h-1a2 2 0 0 0 -2 2v9a2 2 0 0 0 2 2h9a2 2 0 0 0 2 -2v-1"></path><path d="M20.385 6.585a2.1 2.1 0 0 0 -2.97 -2.97l-8.415 8.385v3h3l8.385 -8.415z"></path><path d="M16 5l3 3"></path></svg>
                                </a>
                            </div>
                        </td>
                      </tr>
                    <?php } ?>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        </div>
        
            <?php
        fm_show_footer(); // footer
            exit;
        }
    }

    $objects = is_readable($path) ? scandir($path) : array();
    $folders = array();
    $files = array();
    $current_path = array_slice(explode("/", $path), -1)[0];
    if (is_array($objects) && fm_is_exclude_items($current_path)) {
        foreach ($objects as $file) {
            if ($file == '.' || $file == '..') {
                continue;
            }
            if (!FM_SHOW_HIDDEN && substr($file, 0, 1) === '.') {
                continue;
            }
            $new_path = $path . '/' . $file;
            if (@is_file($new_path) && fm_is_exclude_items($file)) {
                $files[] = $file;
            } elseif (@is_dir($new_path) && $file != '.' && $file != '..' && fm_is_exclude_items($file)) {
                $folders[] = $file;
            }
        }
    }

    if (!empty($files)) {
        natcasesort($files);
    }
    if (!empty($folders)) {
        natcasesort($folders);
    }

    $num_files = count($files);
    $num_folders = count($folders);
    $all_files_size = 0;
    $files_size=array('images'=>0,'videos'=>0,'documents'=>0,'other'=>0);
    ?>
    
        <!-- Page body -->
        <div class="page-body">
          <div class="container-xl">
            <div class="row row-deck row-cards">
                <div class="col-md-6 col-xl-3">
                    <div class="card card-sm">
                        <div class="card-body">
                            <div class="row align-items-center">
                                <div class="col-auto">
                                    <span
                                        class="bg-primary text-white avatar"><!-- Download SVG icon from http://tabler-icons.io/i/currency-dollar -->
                                        <svg xmlns="<?php print_external('icon-2000');?>" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M15 8h.01"></path><path d="M3 6a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v12a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3v-12z"></path><path d="M3 16l5 -5c.928 -.893 2.072 -.893 3 0l5 5"></path><path d="M14 14l1 -1c.928 -.893 2.072 -.893 3 0l3 3"></path></svg>
                                    </span>
                                </div>
                                <div class="col col-images">
                                    <div class="font-weight-medium">
                                        <?php echo lng('Images') ?>
                                    </div>
                                    <div class="text-muted">
                                        <?php echo lng('Calculating File Sizes') ?>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-6 col-xl-3">
                    <div class="card card-sm">
                        <div class="card-body">
                            <div class="row align-items-center">
                                <div class="col-auto">
                                    <span
                                        class="bg-primary text-white avatar">
                                        <svg xmlns="<?php print_external('icon-2000');?>" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M7 4v16l13 -8z"></path></svg>
                                    </span>
                                </div>
                                <div class="col col-videos">
                                    <div class="font-weight-medium">
                                    <?php echo lng('Videos') ?>
                                    </div>
                                    <div class="text-muted">
                                    <?php echo lng('Calculating File Sizes') ?>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-6 col-xl-3">
                    <div class="card card-sm">
                        <div class="card-body">
                            <div class="row align-items-center">
                                <div class="col-auto">
                                    <span
                                        class="bg-primary text-white avatar">
                                        <svg xmlns="<?php print_external('icon-2000');?>" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M15 3v4a1 1 0 0 0 1 1h4"></path><path d="M18 17h-7a2 2 0 0 1 -2 -2v-10a2 2 0 0 1 2 -2h4l5 5v7a2 2 0 0 1 -2 2z"></path><path d="M16 17v2a2 2 0 0 1 -2 2h-7a2 2 0 0 1 -2 -2v-10a2 2 0 0 1 2 -2h2"></path></svg>
                                    </span>
                                </div>
                                <div class="col col-documents">
                                    <div class="font-weight-medium">
                                        <?php echo lng('Documents') ?>
                                    </div>
                                    <div class="text-muted">
                                    <?php echo lng('Calculating File Sizes') ?>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-6 col-xl-3">
                    <div class="card card-sm">
                        <div class="card-body">
                            <div class="row align-items-center">
                                <div class="col-auto">
                                    <span
                                        class="bg-primary text-white avatar">
                                        <svg xmlns="<?php print_external('icon-2000');?>" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M14 3v4a1 1 0 0 0 1 1h4"></path><path d="M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2z"></path></svg>
                                    </span>
                                </div>
                                <div class="col col-other">
                                    <div class="font-weight-medium">
                                    <?php echo lng('OtherFiles') ?>
                                    </div>
                                    <div class="text-muted">
                                    <?php echo lng('Calculating File Sizes') ?>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class='col-12'>
                    <div class="card card-md">
                        <div class="card-body">
                            <div id="table-default" class="table-responsive">
                            <table class="table datatable">
                                <thead>
                                <tr>
                                    <th class="w-1"><input class="form-check-input m-0 align-middle" type="checkbox" aria-label="Select all" onclick="checkbox_toggle()"></th>
                                    <th><button class="table-sort" data-sort="sort-name"><?php echo lng('Name') ?></button></th>
                                    <th class="w-8"><button class="table-sort" data-sort="sort-size"><?php echo lng('Size') ?></button></th>
                                    <th class="w-5"><button class="table-sort" data-sort="sort-type"><?php echo lng('Ext') ?></button></th>
                                    <th class="w-8"><button class="table-sort" data-sort="sort-status"><?php echo lng('Status') ?></button></th>
                                    <th class="col-xl-2"><button class="table-sort" data-sort="sort-date"><?php echo lng('Date') ?></button></th>
                                    <th class="col-xl-2"><button class="table-sort" data-sort="sort-operation"><?php echo lng('Operation') ?></button></th>
                                </tr>
                                </thead>
                                <tbody class="table-tbody">
                                <?php
            // link to parent folder
            if ($parent !== false) {
                ?>
                <tr>
                    <td class="nosort"></td>
                    <td  data-sort><a href="?p=<?php echo urlencode($parent) ?>"><svg xmlns="<?php print_external('icon-2000');?>" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-arrow-left"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M5 12l14 0"></path><path d="M5 12l6 6"></path><path d="M5 12l6 -6"></path></svg>..</a></td>
                    <td data-order></td>
                    <td data-order></td>
                    <td ></td>
                    <td ></td>
                    <td ></td>
                </tr>
                <?php
                }
$ii = 3000;
    foreach ($folders as $f) {
        if (in_array($f, $folders_not_display)) {
            $num_folders--;
            continue;
        }
        $is_link = is_link($path . '/' . $f);
        $img = $is_link ? 'icon-link_folder' : 'fa fa-folder-o';
        $modif_raw = filemtime($path . '/' . $f);
        $modif = date(FM_DATETIME_FORMAT, $modif_raw);
        $date_sorting = strtotime(date("F d Y H:i:s.", $modif_raw));
        $filesize_raw = "";
        $filesize = lng('Folder');
        $perms = substr(decoct(fileperms($path . '/' . $f)), -4);
        if (function_exists('posix_getpwuid') && function_exists('posix_getgrgid')) {
            $owner = posix_getpwuid(fileowner($path . '/' . $f));
            $group = posix_getgrgid(filegroup($path . '/' . $f));
            if ($owner === false) {
                $owner = array('name' => '?');
            }
            if ($group === false) {
                $group = array('name' => '?');
            }
        } else {
            $owner = array('name' => '?');
            $group = array('name' => '?');
        }
        ?>
                                    <tr class="align-middle">
                                        <td><input class="form-check-input m-0 align-middle" type="checkbox" aria-label="Select" id="<?php echo $ii ?>" name="file[]" value="<?php echo fm_enc($f) ?>"></td>
                                        <td  class="sort-name">
                                            <div class="filename"><a href="?p=<?php echo urlencode(trim(FM_PATH . '/' . $f, '/')) ?>" class="text-reset d-block"><?php echo show_folder_icon($external['icon-2000']);?> <?php echo fm_convert_win(fm_enc($f)) ?>
                                                </a><?php echo ($is_link ? ' &rarr; <i>' . readlink($path . '/' . $f) . '</i>' : '') ?></div>
                                        </td>
                                        <td class="sort-size">
                                        </td>
                                        <td class="sort-type">
                                            <?php echo $filesize; ?>
                                        </td>
                                        <td class="sort-status">
                                            
                                        </td>
                                        <td class="sort-date" data-date="<?php echo strtotime($modif);?>"><?php echo $modif ?></td>
                                        <td class="sort-operation">
                                            <div class='btn-list flex-nowrap'>
                                                    <a  data-bs-toggle="modal" data-bs-target="#confirmDailog-modal" data-title="<?php echo lng('Delete').' '.lng('Folder'); ?>" data-name="<?php echo $f?>"  data-url="?p=<?php echo urlencode(FM_PATH) ?>&amp;del=<?php echo urlencode($f) ?>"  class="btn btn-danger btn-icon btn-icon1" data-action="delete" aria-label="delete">
                                                        <svg xmlns="<?php print_external('icon-2000');?>" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-trash"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M4 7l16 0"></path><path d="M10 11l0 6"></path><path d="M14 11l0 6"></path><path d="M5 7l1 12a2 2 0 0 0 2 2h8a2 2 0 0 0 2 -2l1 -12"></path><path d="M9 7v-3a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v3"></path></svg>
                                                    </a>
                                                
                                                    <a  onclick="rename('<?php echo fm_enc(addslashes(FM_PATH)) ?>', '<?php echo fm_enc(addslashes($f)) ?>');return false;" class="btn btn-twitter btn-icon btn-icon1" aria-label="edit">
                                                        <svg xmlns="<?php print_external('icon-2000');?>" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-edit"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M7 7h-1a2 2 0 0 0 -2 2v9a2 2 0 0 0 2 2h9a2 2 0 0 0 2 -2v-1"></path><path d="M20.385 6.585a2.1 2.1 0 0 0 -2.97 -2.97l-8.415 8.385v3h3l8.385 -8.415z"></path><path d="M16 5l3 3"></path></svg>
                                                    </a>
                                                    <a  onclick="copy('<?php echo fm_enc(fm_convert_win(FM_ROOT_PATH.(FM_PATH != '' ? '/' . FM_PATH : ''))) ?>', '<?php echo fm_enc(addslashes($f)) ?>','<?php echo fm_enc(fm_convert_win(FM_ROOT_PATH)) ?>');return false;" class="btn btn-lime btn-icon btn-icon1" aria-label="copy">
                                                        <svg xmlns="<?php print_external('icon-2000');?>" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-copy"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M7 7m0 2.667a2.667 2.667 0 0 1 2.667 -2.667h8.666a2.667 2.667 0 0 1 2.667 2.667v8.666a2.667 2.667 0 0 1 -2.667 2.667h-8.666a2.667 2.667 0 0 1 -2.667 -2.667z"></path><path d="M4.012 16.737a2.005 2.005 0 0 1 -1.012 -1.737v-10c0 -1.1 .9 -2 2 -2h10c.75 0 1.158 .385 1.5 1"></path></svg>
                                                    </a>
                                            </div>
                                        </td>
                                    </tr>
                                    <?php
flush();
        $ii++;
    }
    $ik = 6000;
    foreach ($files as $f) {
        if (in_array($f, $file_not_display)) {
            $num_files--;
            continue;
        }
        $is_link = is_link($path . '/' . $f);
        $img = fm_get_file_icon_class($path . '/' . $f,$external['icon-2000']);
        $modif_raw = filemtime($path . '/' . $f);
        $modif = date(FM_DATETIME_FORMAT, $modif_raw);
        $date_sorting = strtotime(date("F d Y H:i:s.", $modif_raw));
        $filesize_raw = fm_get_size($path . '/' . $f);
        $filesize = fm_get_filesize($filesize_raw);
        $filelink = '?p=' . urlencode(FM_PATH) . '&amp;view=' . urlencode($f);
        $all_files_size += $filesize_raw;
        $perms = substr(decoct(fileperms($path . '/' . $f)), -4);
        if (function_exists('posix_getpwuid') && function_exists('posix_getgrgid')) {
            $owner = posix_getpwuid(fileowner($path . '/' . $f));
            $group = posix_getgrgid(filegroup($path . '/' . $f));
            if ($owner === false) {
                $owner = array('name' => '?');
            }
            if ($group === false) {
                $group = array('name' => '?');
            }
        } else {
            $owner = array('name' => '?');
            $group = array('name' => '?');
        }

        $ext = strtolower(pathinfo($path . '/' . $f, PATHINFO_EXTENSION));
        if(in_array($ext,fm_get_image_exts())){
            $files_size['images']+=$filesize_raw;
        }elseif(in_array($ext,fm_get_video_exts())){
            $files_size['videos']+=$filesize_raw;
        }elseif(in_array($ext,fm_get_text_exts()) || in_array($ext,fm_get_onlineViewer_exts())){
            $files_size['documents']+=$filesize_raw;
        }else{
            $files_size['other']+=$filesize_raw;
        }
        ?>
                                    <tr class="align-middle">
                                        <td><input class="form-check-input m-0 align-middle" type="checkbox" aria-label="Select" id="<?php echo $ik ?>" name="file[]" value="<?php echo fm_enc($f) ?>"></td>
                                        <td class='sort-name'>
                                            <div class="filename">
                                                    <a data-bs-toggle="offcanvas" href="#offcanvas"  aria-controls="offcanvas"   data-name="<?php echo urlencode($f) ?>" data-url="<?php echo fm_enc(FM_ROOT_URL . (!empty($html_path)?'/'.$html_path:'' ).(FM_PATH != '' ? '/' . FM_PATH : '') . '/' . $f) ?>" data-ext="<?php echo $ext ?>" title="<?php echo $f ?>" class="text-reset d-block">
                                                        <?php echo $img ?> <?php echo fm_convert_win(fm_enc($f)) ?>
                                                    </a>
                                                    <?php echo ($is_link ? ' &rarr; <i>' . readlink($path . '/' . $f) . '</i>' : '') ?>
                                            </div>
                                        </td>
                                        <td class="sort-size" ><span title="<?php printf('%s bytes', $filesize_raw)?>">
                                            <?php echo $filesize; ?>
                                            </span></td>
                                        <td class="sort-type"><?php echo $ext ?></td>
                                        <td class="sort-status">
                                            <?php
                                            if($ext=='part'){
                                                echo '<span class="badge bg-orange">'.lng('Uploading').'</span>';
                                            }else{
                                                $file_path='';
                                                if(!empty($html_path)){
                                                    $file_path.=$html_path;
                                                }
                                                if(!empty(FM_PATH)){
                                                    if(!empty($file_path)){
                                                        $file_path.='/';
                                                    }
                                                    $file_path.=FM_PATH;
                                                }
                                                $u_hash=null;
                                                if($_SESSION[FM_SESSION_ID]['user']['type']=='admin'){
                                                    $u_hash=null;
                                                }else{
                                                    $u_hash=$_SESSION[FM_SESSION_ID]['hash'];
                                                }
                                                $fileinfo=getFile_u($pdo,$f,$file_path,$u_hash);
                                                
                                                if(isset($fileinfo) && isset($fileinfo['status']) && $fileinfo['status']==0){
                                                    echo '<span class="badge bg-red">'.lng('Deleted').'</span>';
                                                }
                                            }
                                            ?>
                                        </td>
                                        <td class="sort-date" data-date="<?php echo strtotime($modif);?>"><?php echo $modif ?></td>
                                        <td class="sort-operation">
                                        <div class='btn-list flex-nowrap'> 
                                            <?php if($ext!='part'){ if(!(isset($fileinfo) && isset($fileinfo['status']) && $fileinfo['status']==0)){ ?>
                                                    <a  data-bs-toggle="modal" data-bs-target="#confirmDailog-modal" data-title="<?php echo lng('Delete').' '.lng('File'); ?>" data-name="<?php echo $f ?>"  data-url="?p=<?php echo urlencode(FM_PATH) ?>&amp;del=<?php echo urlencode($f) ?>"  class="btn btn-danger btn-icon btn-icon1" data-action="delete" aria-label="delete">
                                                        <svg xmlns="<?php print_external('icon-2000');?>" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-trash"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M4 7l16 0"></path><path d="M10 11l0 6"></path><path d="M14 11l0 6"></path><path d="M5 7l1 12a2 2 0 0 0 2 2h8a2 2 0 0 0 2 -2l1 -12"></path><path d="M9 7v-3a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v3"></path></svg>
                                                    </a>
                                                
                                                    <a  onclick="rename('<?php echo fm_enc(addslashes(FM_PATH)) ?>', '<?php echo fm_enc(addslashes($f)) ?>');return false;" class="btn btn-twitter btn-icon btn-icon1" aria-label="edit">
                                                        <svg xmlns="<?php print_external('icon-2000');?>" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-edit"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M7 7h-1a2 2 0 0 0 -2 2v9a2 2 0 0 0 2 2h9a2 2 0 0 0 2 -2v-1"></path><path d="M20.385 6.585a2.1 2.1 0 0 0 -2.97 -2.97l-8.415 8.385v3h3l8.385 -8.415z"></path><path d="M16 5l3 3"></path></svg>
                                                    </a>
                                                
                                                    <a onclick="copy('<?php echo fm_enc(fm_convert_win(FM_ROOT_PATH.(FM_PATH != '' ? '/' . FM_PATH : ''))) ?>', '<?php echo fm_enc(addslashes($f)) ?>','<?php echo fm_enc(fm_convert_win(FM_ROOT_PATH)) ?>');return false;"  class="btn btn-lime btn-icon btn-icon1" aria-label="copy">
                                                        <svg xmlns="<?php print_external('icon-2000');?>" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-copy"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M7 7m0 2.667a2.667 2.667 0 0 1 2.667 -2.667h8.666a2.667 2.667 0 0 1 2.667 2.667v8.666a2.667 2.667 0 0 1 -2.667 2.667h-8.666a2.667 2.667 0 0 1 -2.667 -2.667z"></path><path d="M4.012 16.737a2.005 2.005 0 0 1 -1.012 -1.737v-10c0 -1.1 .9 -2 2 -2h10c.75 0 1.158 .385 1.5 1"></path></svg>
                                                    </a>
                                                <?php } 
                                                    if(in_array($ext,['zip','tar'])){
                                                ?>

                                                <a onclick="unzip('<?php echo fm_enc(fm_convert_win(FM_ROOT_PATH.(FM_PATH != '' ? '/' . FM_PATH : ''))) ?>', '<?php echo fm_enc(addslashes($f)) ?>','<?php echo fm_enc(fm_convert_win(FM_ROOT_PATH)) ?>');return false;" target="_blank" class="btn btn-azure btn-icon btn-icon1" aria-label="unzip" title="<?php echo lng('unzip');?>">
                                                        <svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-file-zip"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M6 20.735a2 2 0 0 1 -1 -1.735v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2h-1"></path><path d="M11 17a2 2 0 0 1 2 2v2a1 1 0 0 1 -1 1h-2a1 1 0 0 1 -1 -1v-2a2 2 0 0 1 2 -2z"></path><path d="M11 5l-1 0"></path><path d="M13 7l-1 0"></path><path d="M11 9l-1 0"></path><path d="M13 11l-1 0"></path><path d="M11 13l-1 0"></path><path d="M13 15l-1 0"></path></svg>
                                                    </a>
                                                    <?php } ?>

                                                    <a href="<?php echo fm_enc(FM_ROOT_URL . (!empty($html_path)?'/'.$html_path:'' ).(FM_PATH != '' ? '/' . FM_PATH : '') . '/' . $f) ?>" target="_blank" class="btn btn-teal btn-icon btn-icon1" aria-label="link">
                                                        <svg xmlns="<?php print_external('icon-2000');?>" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-link"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M9 15l6 -6"></path><path d="M11 6l.463 -.536a5 5 0 0 1 7.071 7.072l-.534 .464"></path><path d="M13 18l-.397 .534a5.068 5.068 0 0 1 -7.127 0a4.972 4.972 0 0 1 0 -7.071l.524 -.463"></path></svg>
                                                    </a>
                                                
                                                    <a  data-bs-toggle="modal" data-bs-target="#confirmDailog-modal" data-title="<?php echo lng('Download'); ?>" data-name="<?php echo $f ?>"  data-url="?p=<?php echo urlencode(FM_PATH) ?>&amp;dl=<?php echo urlencode($f) ?>" class="btn btn-cyan btn-icon btn-icon1" data-action="download" aria-label="download">
                                                        <svg xmlns="<?php print_external('icon-2000');?>" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-download"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2 -2v-2"></path><path d="M7 11l5 5l5 -5"></path><path d="M12 4l0 12"></path></svg>
                                                    </a>
                                                    <?php } ?>
                                            </div>
                                        </td>
                                    </tr>
                                    <?php
flush();
        $ik++;
    }
    ?>
                                </tbody>
                                <?php if (empty($folders) && empty($files)) { ?>
                                <tfoot>
                                    <tr><?php if (!FM_READONLY): ?>
                                            <td></td><?php endif; ?>
                                        <td colspan="<?php echo (!FM_IS_WIN && !$hide_Cols) ? '6' : '6' ?>"><em><?php echo lng('Folder is empty') ?></em></td>
                                    </tr>
                                </tfoot>
                                <?php
                            } else { ?>
                                <tfoot>
                                    <tr>
                                        <td class="gray border-0" colspan="6">
                                            <?php echo lng('FullSize').': <span class="badge text-bg-light border-radius-0">'.fm_get_filesize($all_files_size).'</span>' ?>
                                            <?php echo lng('File').': <span class="badge text-bg-light border-radius-0">'.$num_files.'</span>' ?>
                                            <?php echo lng('Folder').': <span class="badge text-bg-light border-radius-0">'.$num_folders.'</span>' ?>
                                        </td>
                                    </tr>
                                </tfoot>
                                <?php } ?>
                            </table>
                            <input type="hidden" name="col-images" id="col-images" value="<?php echo fm_get_filesize($files_size['images']);?>">
                            <input type="hidden" name="col-videos" id="col-videos" value="<?php echo fm_get_filesize($files_size['videos']);?>">
                            <input type="hidden" name="col-documents" id="col-documents" value="<?php echo fm_get_filesize($files_size['documents']);?>">
                            <input type="hidden" name="col-other" id="col-other" value="<?php echo fm_get_filesize($files_size['other']);?>">
                            </div>
                            <div class="col-12">
                                <div class="col-xs-12">
                                    <ul class="list-inline footer-action" >
                                        <li class="list-inline-item py-1"> <a href="#/select-all" class="btn btn-small btn-outline-primary btn-2" onclick="select_all();return false;"><svg xmlns="<?php print_external('icon-2000');?>" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-square-check"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M3 3m0 2a2 2 0 0 1 2 -2h14a2 2 0 0 1 2 2v14a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2z"></path><path d="M9 12l2 2l4 -4"></path></svg> <?php echo lng('SelectAll') ?> </a></li>

                                        <li class="list-inline-item py-1"><a href="#/unselect-all" class="btn btn-small btn-outline-primary btn-2" onclick="unselect_all();return false;"><svg xmlns="<?php print_external('icon-2000');?>" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-square-x"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M3 5a2 2 0 0 1 2 -2h14a2 2 0 0 1 2 2v14a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2v-14z"></path><path d="M9 9l6 6m0 -6l-6 6"></path></svg> <?php echo lng('UnSelectAll') ?> </a></li>

                                        <li class="list-inline-item py-1"><a href="#/invert-all" class="btn btn-small btn-outline-primary btn-2" onclick="invert_all();return false;"><svg xmlns="<?php print_external('icon-2000');?>" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-list"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M9 6l11 0"></path><path d="M9 12l11 0"></path><path d="M9 18l11 0"></path><path d="M5 6l0 .01"></path><path d="M5 12l0 .01"></path><path d="M5 18l0 .01"></path></svg> <?php echo lng('InvertSelection') ?> </a></li>

                                        <li class="list-inline-item py-1"><a onclick="pack('<?php echo lng('Delete selected files and folders?'); ?>', 'delete');return false;"class="btn btn-small btn-outline-primary btn-2"><svg xmlns="<?php print_external('icon-2000');?>" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-trash"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M4 7l16 0"></path><path d="M10 11l0 6"></path><path d="M14 11l0 6"></path><path d="M5 7l1 12a2 2 0 0 0 2 2h8a2 2 0 0 0 2 -2l1 -12"></path><path d="M9 7v-3a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v3"></path></svg> <?php echo lng('Delete') ?> </a></li>
                                            
                                        <li class="list-inline-item py-1"><a onclick="pack('<?php echo lng('Create archive?'); ?>', 'zip');return false;" class="btn btn-small btn-outline-primary btn-2"><svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-file-zip"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M6 20.735a2 2 0 0 1 -1 -1.735v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2h-1"></path><path d="M11 17a2 2 0 0 1 2 2v2a1 1 0 0 1 -1 1h-2a1 1 0 0 1 -1 -1v-2a2 2 0 0 1 2 -2z"></path><path d="M11 5l-1 0"></path><path d="M13 7l-1 0"></path><path d="M11 9l-1 0"></path><path d="M13 11l-1 0"></path><path d="M11 13l-1 0"></path><path d="M13 15l-1 0"></path></svg> <?php echo lng('Zip') ?> </a></li>

                                        <!-- <li class="list-inline-item"><a onclick="pack('<?php echo lng('Create archive?'); ?>', 'tar');return false;"  class="btn btn-small btn-outline-primary btn-2"><svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-file-zip"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M6 20.735a2 2 0 0 1 -1 -1.735v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2h-1"></path><path d="M11 17a2 2 0 0 1 2 2v2a1 1 0 0 1 -1 1h-2a1 1 0 0 1 -1 -1v-2a2 2 0 0 1 2 -2z"></path><path d="M11 5l-1 0"></path><path d="M13 7l-1 0"></path><path d="M11 9l-1 0"></path><path d="M13 11l-1 0"></path><path d="M11 13l-1 0"></path><path d="M13 15l-1 0"></path></svg> <?php echo lng('Tar') ?> </a></li> -->

                                        <li class="list-inline-item py-1"><a onclick="copy('<?php echo fm_enc(fm_convert_win(FM_ROOT_PATH.(FM_PATH != '' ? '/' . FM_PATH : ''))) ?>', '','<?php echo fm_enc(fm_convert_win(FM_ROOT_PATH)) ?>',1);return false;" class="btn btn-small btn-outline-primary btn-2"><svg xmlns="<?php print_external('icon-2000');?>" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-copy"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M7 7m0 2.667a2.667 2.667 0 0 1 2.667 -2.667h8.666a2.667 2.667 0 0 1 2.667 2.667v8.666a2.667 2.667 0 0 1 -2.667 2.667h-8.666a2.667 2.667 0 0 1 -2.667 -2.667z"></path><path d="M4.012 16.737a2.005 2.005 0 0 1 -1.012 -1.737v-10c0 -1.1 .9 -2 2 -2h10c.75 0 1.158 .385 1.5 1"></path></svg> <?php echo lng('Copy') ?> </a></li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
          </div>
        </div>
      </div>
<?php
fm_show_footer(); // footer
 
?>
<?php
function print_external($key)
{
    global $external;

    if (!array_key_exists($key, $external)) {
        // throw new Exception('Key missing in external: ' . key);
        echo "<!-- EXTERNAL: MISSING KEY $key -->";
        return;
    }

    echo "$external[$key]";
}

/**
 * Show nav block
 * @param string $path
 */
function fm_show_nav_path($path,$nav)
{
    global $lang, $sticky_navbar, $editFile;
    $isStickyNavBar = $sticky_navbar ? 'fixed-top' : '';
    ?>
    <div class="page-wrapper">
        <!-- Page header -->
        <div class="page-header d-print-none">
            <div class="container-xl">
            <div class="row g-2 align-items-center">
                <div class="col">
                <h2 class="page-title">
                <?php
                $path = fm_clean_path($path);
                if($nav=='home'){
                    $root_url = "<a href='?p='>".lng('Home')." </a> ";
                }elseif($nav=='users'){
                    $root_url = "<a href='?nav=users'>".lng('Users')." </a> ";
                }elseif($nav=='logs'){
                    $root_url = "<a href='?nav=logs'>".lng('Logs')." </a> ";
                }elseif($nav=='settings'){
                    $root_url = "<a href='?nav=settings'>".lng('Settings')." </a> ";
                }else{
                    $root_url = "<a href='?p='>".lng('Home')." </a> ";
                }
                
                $sep = '/';
                if ($path != '') {
                    $exploded = explode('/', $path);
                    $count = count($exploded);
                    $array = array();
                    $parent = '';
                    for ($i = 0; $i < $count; $i++) {
                        $parent = trim($parent . '/' . $exploded[$i], '/');
                        $parent_enc = urlencode($parent);
                        $array[] = " <a href='?p={$parent_enc}'> " . fm_enc(fm_convert_win($exploded[$i])) . "</a>";
                    }
                    $root_url .= $sep . implode($sep, $array);
                }
                echo  $root_url . $editFile ;
                ?>
                </h2>
                </div>
                <!-- Page title actions -->
                <div class="col-auto ms-auto d-print-none">
                <div class="btn-list">
                    <?php 
                    if($nav=='home'){
                        ?>
                 
                    <a class="btn d-none d-sm-inline-block" data-bs-toggle="modal" data-bs-target="#modal-upload" aria-label="<?php echo lng('UploadingFiles'); ?>">
                        <svg xmlns="<?php print_external('icon-2000');?>" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M14 20h-8a2 2 0 0 1 -2 -2v-12a2 2 0 0 1 2 -2h12v5" /><path d="M11 16h-5a2 2 0 0 0 -2 2" /><path d="M15 16l3 -3l3 3" /><path d="M18 13v9" /></svg>
                        <?php echo lng('UploadingFiles'); ?>
                    </a>
                    <a class="btn d-sm-none btn-icon" data-bs-toggle="modal" data-bs-target="#modal-upload">
                        <svg xmlns="<?php print_external('icon-2000');?>" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M14 20h-8a2 2 0 0 1 -2 -2v-12a2 2 0 0 1 2 -2h12v5" /><path d="M11 16h-5a2 2 0 0 0 -2 2" /><path d="M15 16l3 -3l3 3" /><path d="M18 13v9" /></svg>
                    </a>
                  <a  class="btn d-none d-sm-inline-block" data-bs-toggle="modal" data-bs-target="#modal-folder">
                    <svg xmlns="<?php print_external('icon-2000');?>" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M12 5l0 14"></path><path d="M5 12l14 0"></path></svg>
                    <?php echo lng('NewItem'); ?>
                  </a>
                  <a  class="btn  d-sm-none btn-icon" data-bs-toggle="modal" data-bs-target="#modal-folder" aria-label="<?php echo lng('NewItem'); ?>">
                    <svg xmlns="<?php print_external('icon-2000');?>" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M12 5l0 14"></path><path d="M5 12l14 0"></path></svg>
                  </a>
                  <?php }elseif($nav=='users'){ if($_SESSION[FM_SESSION_ID]['user']['type']=='admin'){ ?>
                    <a  class="btn d-none d-sm-inline-block" onclick="edit('add','<?php echo lng('Create User'); ?>', '');return false;">
                    <svg xmlns="<?php print_external('icon-2000');?>" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M12 5l0 14"></path><path d="M5 12l14 0"></path></svg>
                    <?php echo lng('Create User'); ?>

                    <a  class="btn d-sm-none btn-icon" onclick="edit('add','<?php echo lng('Create User'); ?>', '');return false;" aria-label="<?php echo lng('Create User'); ?>">
                    <svg xmlns="<?php print_external('icon-2000');?>" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M12 5l0 14"></path><path d="M5 12l14 0"></path></svg>
                  </a>
                 <?php } } ?>
                </div>
                </div>
            </div>
            </div>
        </div>
    <?php
}

/**
 * Show alert message from session
 */
function fm_show_message()
{
    if (isset($_SESSION[FM_SESSION_ID]['message'])) {
        $class = isset($_SESSION[FM_SESSION_ID]['status']) ? $_SESSION[FM_SESSION_ID]['status'] : 'ok';
        echo '<p class="message ' . $class . '">' . $_SESSION[FM_SESSION_ID]['message'] . '</p>';
        unset($_SESSION[FM_SESSION_ID]['message']);
        unset($_SESSION[FM_SESSION_ID]['status']);
    }
}

/**
 * Show page header after login
 */
function fm_show_header($nav,$path)
{
    header("Content-Type: text/html; charset=utf-8");
    header("Expires: Sat, 26 Jul 1997 05:00:00 GMT");
    header("Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0");
    header("Pragma: no-cache");

    $getTheme = fm_get_theme();
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"/>
    <meta http-equiv="X-UA-Compatible" content="ie=edge"/>
    <title><?php echo fm_enc(APP_TITLE) ?></title>
    <?php print_external('css-dropzone');?>
    <?php print_external('css-tabler');?>
    <?php print_external('css-tabler-flags');?>
    <?php print_external('css-tabler-payments');?>
    <?php print_external('css-tabler-vendors');?>
    <?php print_external('css-bootstrap');?>
    <?php print_external('css-style');?>
    <?php print_external('css-toastr');?>
    <?php print_external('css-datatables');?>
    
    <script type="text/javascript">window.csrf = '<?php echo $_SESSION['token']; ?>';</script>
    <style>
        @import url('https://rsms.me/inter/inter.css');
        :root {
      	    --tblr-font-sans-serif: 'Inter Var', -apple-system, BlinkMacSystemFont, San Francisco, Segoe UI, Roboto, Helvetica Neue, sans-serif;
        }
        body {
      	    font-feature-settings: "cv03", "cv04", "cv11";
        }
        .nav-item-n{min-width: 92px;}
        .btn-icon1 {
            min-width:calc(var(--tblr-btn-line-height) * var(--tblr-btn-font-size) + var(--tblr-btn-padding-y) * 1.2 + var(--tblr-btn-border-width) * 1.2);
            min-height:calc(var(--tblr-btn-line-height) * var(--tblr-btn-font-size) + var(--tblr-btn-padding-y) * 1.2 + var(--tblr-btn-border-width) * 1.2);
            padding-left:0;
            padding-right:0
        }
        .preview-video { position:relative;max-width:100%;height:0;padding-bottom:62.5%;margin-bottom:10px  }
        .preview-video video { position:absolute;width:100%;height:100%;left:0;top:0;background:#000  }
        .icon-green{color:#2fb344;}
        .icon-blue{color:#206bc4;}
        .icon-red{color:#d63939;}
        code{
            padding:2px 0;
        }
        .offcanvas,.offcanvas-lg,.offcanvas-md,.offcanvas-sm,.offcanvas-xl,.offcanvas-xxl {
            --tblr-offcanvas-width:680px;
            }
        .datagrid {
            --tblr-datagrid-item-width:30rem;
        }
        .line{border-bottom:var(--tblr-border-width) var(--tblr-border-style) rgba(4,32,69,.14);height: 2px;padding:1rem 0 0 0;}
    </style>
</head>
<body data-bs-theme="<?php echo $getTheme;?>">

    <!--上传文件-->
    <div class="modal modal-blur fade" id="modal-upload" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog modal-lg modal-dialog-centered" role="document">
        <div class="modal-content">
            <div class="modal-header">
            <h5 class="modal-title"><?php echo lng('UploadingFiles') ?></h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
            <div class="mb-3">
                <form class="dropzone" id="fileUploader" action="<?php echo htmlspecialchars(FM_SELF_URL) . '?p=' . fm_enc(FM_PATH) ?>" autocomplete="off" enctype="multipart/form-data">
                    <input type="hidden" name="p" value="<?php echo fm_enc(FM_PATH) ?>">
                    <input type="hidden" name="fullpath" id="fullpath" value="<?php echo fm_enc(FM_PATH) ?>">
                    <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                    <div class="fallback">
                        <input name="file" type="file"  multiple/>
                    </div>
                </form>
            </div>
            </div>
            <div class="modal-footer">
                <a  class="btn btn-link link-secondary" data-bs-dismiss="modal">
                    <?php echo lng('Cancel') ?>
                </a>
            </div>
        </div>
        </div>
    </div>

    <!--新增文件夹-->
    <div class="modal modal-blur fade" id="modal-folder" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog modal-lg modal-dialog-centered" role="document">
        <div class="modal-content">
            <div class="modal-header">
            <h5 class="modal-title"><?php echo lng('NewItem') ?></h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <form method="post" id="create-folder-form" novalidate>
            <div class="modal-body">
                <div class="mb-3">
                    <label class="form-label"><?php echo lng('Name') ?></label>
                    <input type="text" class="form-control" name="newfilename" placeholder="">
                    <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                </div>
            </div>
            <div class="modal-footer">
                <a  class="btn btn-link link-secondary" data-bs-dismiss="modal">
                    <?php echo lng('Cancel') ?>
                </a>
                <button type="submit"   class="btn btn-success ms-auto" data-bs-dismiss="modal">
                    <?php echo lng('Save') ?> 
                </button>
            </div>
            </form>
        </div>
        </div>
    </div>
    
    <!--重命名-->
    <div class="modal modal-blur fade" id="modal-rename" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog modal-lg modal-dialog-centered" role="document">
        <div class="modal-content">
            <div class="modal-header">
            <h5 class="modal-title"><?php echo lng('Rename') ?></h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <form method="post" id="rename_form" novalidate>
            <div class="modal-body">
                <div class="mb-3">
                    <label class="form-label"><?php echo lng('Name') ?></label>
                    <input type="text" class="form-control" name="rename_to" id="js-rename-to">
                    <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                    <input type="hidden" name="rename_from" id="js-rename-from">
                </div>
            </div>
            <div class="modal-footer">
                <a  class="btn btn-link link-secondary" data-bs-dismiss="modal">
                    <?php echo lng('Cancel') ?>
                </a>
                <button type="submit"   class="btn btn-success ms-auto" data-bs-dismiss="modal">
                    <?php echo lng('Save') ?> 
                </button>
            </div>
            </form>
        </div>
        </div>
    </div>

    <!--提醒-->
    <div id="confirmDailog-div">
        <div class="modal modal-blur fade confirmDailog" id="confirmDailog-modal" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog modal-sm modal-dialog-centered" role="document" >
            <div class="modal-content">
                <form id="confirmDailog-form" method="post"  action="<%this.action%>">
                <div class="modal-status bg-danger"></div>
                <div class="modal-body  text-center py-4">
                    <svg xmlns="<?php print_external('icon-2000');?>" class="icon mb-2 text-danger icon-lg" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M10.24 3.957l-8.422 14.06a1.989 1.989 0 0 0 1.7 2.983h16.845a1.989 1.989 0 0 0 1.7 -2.983l-8.423 -14.06a1.989 1.989 0 0 0 -3.4 0z" /><path d="M12 9v4" /><path d="M12 17h.01" /></svg>
                    <h3><?php echo lng('Are you sure?') ?> </h3>
                    <div class="text-muted modal-content-t"><%this.content%></div>
                </div>
                <div class="modal-footer">
                    <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                    <button type="button" class="btn btn-link link-secondary me-auto" data-bs-dismiss="modal"><?php echo lng('Cancel') ?></button>
                    <button type="submit" class="btn btn-danger" data-bs-dismiss="modal"><?php echo lng('Okay') ?> </button>
                </div>
            </form>
            </div>
        </div>
        </div>
    </div>

    <!--文件打包、多个删除 提醒-->
    <div class="modal modal-blur fade" id="modal-pack" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog modal-lg modal-dialog-centered" role="document" >
            <div class="modal-content">
                <div class="modal-header other-div">
                    <h5 class="modal-title pack-content" ><?php echo lng('Create archive?') ?></h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form id="pack-form" method="post" novalidate>
                    <div class="modal-body other-div">
                        <div class="mb-3">
                            <label class="form-label"><?php echo lng('Name') ?></label>
                            <input type="text" class="form-control" name="packname" placeholder="<?php echo lng('Archive') ?> <?php echo lng('Name') ?>">
                        </div>
                        <label class="form-label"></label>
                        <div class="form-selectgroup-boxes row">
                            <div class="col-lg-3 mb-3">
                                <label class="form-selectgroup-item">
                                <input type="radio" name="type" value="zip" class="form-selectgroup-input" checked>
                                <span class="form-selectgroup-label d-flex align-items-center p-3">
                                    <span class="me-3">
                                    <span class="form-selectgroup-check"></span>
                                    </span>
                                    <span class="form-selectgroup-label-content">
                                    <span class="form-selectgroup-title strong mb-1"><?php echo lng('Zip') ?></span>
                                    </span>
                                </span>
                                </label>
                            </div>
                            <div class="col-lg-3  mb-3">
                                <label class="form-selectgroup-item">
                                <input type="radio" name="type" value="tar" class="form-selectgroup-input">
                                <span class="form-selectgroup-label d-flex align-items-center p-3">
                                    <span class="me-3">
                                    <span class="form-selectgroup-check"></span>
                                    </span>
                                    <span class="form-selectgroup-label-content">
                                    <span class="form-selectgroup-title strong mb-1"><?php echo lng('Tar') ?></span>
                                    </span>
                                </span>
                                </label>
                            </div>
                        </div>
                    </div>
                    <div class="modal-body delete-div  text-center py-4">
                        <svg xmlns="<?php print_external('icon-2000');?>" class="icon mb-2 text-danger icon-lg" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M10.24 3.957l-8.422 14.06a1.989 1.989 0 0 0 1.7 2.983h16.845a1.989 1.989 0 0 0 1.7 -2.983l-8.423 -14.06a1.989 1.989 0 0 0 -3.4 0z" /><path d="M12 9v4" /><path d="M12 17h.01" /></svg>
                        <h3><?php echo lng('Are you sure?') ?></h3>
                        <div class="text-muted modal-content-t pack-content"><%this.content%></div>
                    </div>
                <div class="modal-footer">
                    <input type="hidden" name="group" value="1">
                    <input type="hidden" name="file" value="">
                    <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                    <button type="button" class="btn btn-link link-secondary me-auto" data-bs-dismiss="modal"><?php echo lng('Cancel') ?></button>
                    <button type="submit" class="btn btn-primary" data-bs-dismiss="modal"><?php echo lng('Execute') ?> </button>
                </div>
            </form>
            </div>
        </div>
    </div>

    <!--解压缩 提醒-->
    <div class="modal modal-blur fade" id="unzip-modal" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog modal-lg modal-dialog-centered" role="document" >
            <div class="modal-content">
                <div class="modal-header other-div">
                    <h5 class="modal-title pack-content" ><?php echo lng('unzip') ?></h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form id="unzip-form" method="post" novalidate>
                    <div class="modal-body other-div">
                        <div class="mb-3">
                            <label class="form-label"><?php echo lng('Files') ?>：</label>
                            <input type="text" id="file-name" class="form-control" disabled>
                            <input type="hidden" name="unzip" value="">
                        </div>
                        <div class="mb-3">
                        <label class="form-label"><?php echo lng('UnZipToFolder') ?>：</label>
                        <div class="input-group mb-2">
                            <span class="input-group-text" id="path-folder">/</span>
                            <input type="text" name="tofolder" id="tofolder" class="form-control" placeholder="mind/nested/folder">
                        </div>
                    </div>
                    </div>
                <div class="modal-footer">
                    <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                    <button type="button" class="btn btn-link link-secondary me-auto" data-bs-dismiss="modal"><?php echo lng('Cancel') ?></button>
                    <button type="submit" class="btn btn-primary" data-bs-dismiss="modal"><?php echo lng('Execute') ?> </button>
                </div>
            </form>
            </div>
        </div>
    </div>

    <!--复制或移动-->
    <div class="modal modal-blur fade" id="modal-copy" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog modal-lg modal-dialog-centered" role="document">
        <div class="modal-content">
            <div class="modal-header">
            <h5 class="modal-title"><?php echo lng('Copy or Move Files') ?> </h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <form method="post" id="copy-file-form" novalidate>
            <div class="modal-body">
                <div class="mb-3">
                    <label class="form-label"><?php echo lng('Files') ?>：</label>
                    <input type="text" id="file-name" class="form-control" disabled>
                    <input type="hidden" name="file" value=""><!--提交文件内容 一个或者多个组-->
                </div>
                <div class="mb-3">
                    <label class="form-label"><?php echo lng('SourceFolder') ?>：</label>
                    <input type="text" id="old-folder" class="form-control" disabled>
                </div>
                <div class="mb-3">
                    <label class="form-label"><?php echo lng('DestinationFolder') ?>：</label>
                    <div class="input-group mb-2">
                        <span class="input-group-text" id="path-folder">/</span>
                        <input type="text" name="copy_to" id="copy_to" class="form-control" placeholder="mind/nested/folder">
                    </div>
                </div>
                <label class="form-label"></label>
                <div class="form-selectgroup-boxes row">
                    <div class="col-lg-3  mb-3">
                        <label class="form-selectgroup-item">
                        <input type="radio" name="copy_type" value="1" class="form-selectgroup-input" checked>
                        <span class="form-selectgroup-label d-flex align-items-center p-3">
                            <span class="me-3">
                            <span class="form-selectgroup-check"></span>
                            </span>
                            <span class="form-selectgroup-label-content">
                            <span class="form-selectgroup-title strong mb-1"><?php echo lng('Copy') ?></span>
                            </span>
                        </span>
                        </label>
                    </div>
                    <div class="col-lg-3  mb-3">
                        <label class="form-selectgroup-item">
                        <input type="radio" name="copy_type" value="2" class="form-selectgroup-input">
                        <span class="form-selectgroup-label d-flex align-items-center p-3">
                            <span class="me-3">
                            <span class="form-selectgroup-check"></span>
                            </span>
                            <span class="form-selectgroup-label-content">
                            <span class="form-selectgroup-title strong mb-1"><?php echo lng('Move') ?></span>
                            </span>
                        </span>
                        </label>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                <button type="button" class="btn btn-link link-secondary me-auto" data-bs-dismiss="modal"><?php echo lng('Cancel') ?></button>
                <button type="submit" class="btn btn-success" data-bs-dismiss="modal"><?php echo lng('Execute') ?></button>
            </div>
            </form>
        </div>
        </div>
    </div>
   
    <!--添加用户-->
    <div class="modal modal-blur fade" id="modal-users" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog modal-lg modal-dialog-centered" role="document">
        <div class="modal-content">
            <div class="modal-header">
            <h5 class="modal-title"><?php echo lng('Create User') ?></h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <form method="post" id="create-user-form" novalidate>
            <div class="modal-body">
                <div class="row">
                    <div class="col-lg-8">
                        <div class="mb-3">
                            <label class="form-label"><?php echo lng('Username') ?></label>
                            <input type="text" class="form-control" name="name" placeholder="">
                        </div>
                    </div>
                    <div class="col-lg-4">
                        <div class="mb-3">
                        <label class="form-label"><?php echo lng('UserType') ?></label>
                        <select class="form-select" name="type">
                            <option value="admin" selected>admin</option>
                            <option value="third">third</option>
                        </select>
                        </div>
                    </div>
                </div>
                <div class="mb-3">
                    <label class="form-label"><?php echo lng('Password') ?></label>
                    <input type="password" class="form-control" name="password" placeholder="">
                </div>
                <div class="mb-3">
                    <label class="form-label"><?php echo lng('Email') ?></label>
                    <input type="text" class="form-control" name="email" placeholder="">
                </div>
                <div class="row">
                    <div class="col-lg-8">
                        <div class="mb-3">
                        <label class="form-label"><?php echo lng('Path') ?></label>
                        <div class="input-group input-group-flat">
                            <input type="text" class="form-control" name="path"  value="" autocomplete="off">
                        </div>
                        </div>
                    </div>
                    <div class="col-lg-4">
                        <div class="mb-3">
                        <label class="form-label"><?php echo lng('DeletePermissions') ?></label>
                        <select class="form-select" name="delete_perm">
                            <option value="1" selected><?php echo lng('deletion') ?></option>
                            <option value="2" ><?php echo lng('Mark deletion') ?></option>
                        </select>
                        </div>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <a  class="btn btn-link link-secondary" data-bs-dismiss="modal">
                    <?php echo lng('Cancel') ?>
                </a>
                <button type="submit"   class="btn btn-success ms-auto" data-bs-dismiss="modal">
                    <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                    <input type="hidden" name="user_hash" value="">
                    <?php echo lng('Save') ?>
                </button>
            </div>
            </form>
        </div>
        </div>
    </div>

    <!--删除用户提醒-->
    <div id="confirmDailog-div">
        <div class="modal modal-blur fade confirmDailog" id="confirmDailog-user-modal" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog modal-sm modal-dialog-centered" role="document" >
            <div class="modal-content">
                <form id="confirmDailog-user-form" method="post"  action="<%this.action%>">
                <div class="modal-status bg-danger"></div>
                <div class="modal-body  text-center py-4">
                    <svg xmlns="<?php print_external('icon-2000');?>" class="icon mb-2 text-danger icon-lg" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M10.24 3.957l-8.422 14.06a1.989 1.989 0 0 0 1.7 2.983h16.845a1.989 1.989 0 0 0 1.7 -2.983l-8.423 -14.06a1.989 1.989 0 0 0 -3.4 0z" /><path d="M12 9v4" /><path d="M12 17h.01" /></svg>
                    <h3><?php echo lng('Are you sure?') ?> </h3>
                    <div class="text-muted modal-content-t"><%this.content%></div>
                    <div class="form-selectgroup-boxes row mt-3">
                        <div class="col-lg-12">
                            <label class="form-selectgroup-item">
                            <input type="radio" name="confirm" value="1" class="form-selectgroup-input">
                            <span class="form-selectgroup-label d-flex align-items-center p-3">
                                <span class="me-3">
                                <span class="form-selectgroup-check"></span>
                                </span>
                                <span class="form-selectgroup-label-content">
                                <span class="form-selectgroup-title strong mb-1"><?php echo lng('Confirm deleting all uploaded files related to the user') ?></span>
                                </span>
                            </span>
                            </label>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                    <button type="button" class="btn btn-link link-secondary me-auto" data-bs-dismiss="modal"><?php echo lng('Cancel') ?></button>
                    <button type="submit" class="btn btn-danger" data-bs-dismiss="modal"><?php echo lng('Okay') ?> </button>
                </div>
            </form>
            </div>
        </div>
        </div>
    </div>

    <!--详情-->
    <div class="offcanvas offcanvas-end" tabindex="-1" id="offcanvas" aria-labelledby="offcanvasEndLabel">
        <div class="offcanvas-header">
            <h2 class="offcanvas-title" id="offcanvasEndLabel" style="word-wrap: break-word;"><?php echo lng('Details') ?></h2>
            <button type="button" class="btn btn-primary" data-bs-dismiss="offcanvas" aria-label="Close"><?php echo lng('Close') ?> </button>
        </div>
        <div class="offcanvas-body">
            <div id="offcanvas-content">
                
            </div>
            <div class="line"></div>
            <div class="datagrid" style="margin-top: 1rem;">
                <div class="datagrid-item">
                    <div class="datagrid-title"><?php echo lng('Name') ?> </div>
                    <div class="datagrid-content" id="detail-name"></div>
                </div>
                <div class="datagrid-item">
                    <div class="datagrid-title"><?php echo lng('Size') ?></div>
                    <div class="datagrid-content" id="detail-size"></div>
                </div>
                <div class="datagrid-item">
                    <div class="datagrid-title"><?php echo lng('Ext') ?></div>
                    <div class="datagrid-content" id="detail-ext"></div>
                </div>
                <div class="datagrid-item">
                    <div class="datagrid-title"><?php echo lng('Date') ?></div>
                    <div class="datagrid-content" id="detail-date"></div>
                </div>
            </div>
            <div class="mt-3">
            </div>
        </div>
    </div>

    <!--修改密码-->
    <div class="modal modal-blur fade" id="modal-password" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog modal-lg modal-dialog-centered" role="document">
        <div class="modal-content">
            <div class="modal-header">
            <h5 class="modal-title"><?php echo lng('Change').lng('Password') ?></h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <form method="post" id="change-password-form" novalidate>
            <div class="modal-body">
                <div class="mb-3">
                    <label class="form-label"><?php echo lng('Password') ?></label>
                    <input type="password" class="form-control" name="password" placeholder="">
                    <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                </div>
            </div>
            <div class="modal-footer">
                <a  class="btn btn-link link-secondary" data-bs-dismiss="modal">
                    <?php echo lng('Cancel') ?>
                </a>
                <button type="submit"   class="btn btn-success ms-auto" data-bs-dismiss="modal">
                    <?php echo lng('Save') ?> 
                </button>
            </div>
            </form>
        </div>
        </div>
    </div>

        <div class="page">
        <header class="navbar navbar-expand-md d-print-none" >
        <div class="container-xl">
          <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbar-menu" aria-controls="navbar-menu" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
          </button>
          <h1 class="navbar-brand navbar-brand-autodark d-none-navbar-horizontal pe-0 pe-md-3">
            <a href=".">
              <img src="<?php print_external('logo');?>" width="110" height="32" alt="Tabler" class="navbar-brand-image">
            </a>
          </h1>
          <div class="navbar-nav flex-row order-md-last">
            <div class="d-none d-md-flex">
              <a href="?theme=dark" class="nav-link px-0 hide-theme-dark" title="Enable dark mode" data-bs-toggle="tooltip"
		   data-bs-placement="bottom">
                <svg xmlns="<?php print_external('icon-2000');?>" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M12 3c.132 0 .263 0 .393 0a7.5 7.5 0 0 0 7.92 12.446a9 9 0 1 1 -8.313 -12.454z" /></svg>
              </a>
              <a href="?theme=light" class="nav-link px-0 hide-theme-light" title="Enable light mode" data-bs-toggle="tooltip"
		   data-bs-placement="bottom">
                <svg xmlns="<?php print_external('icon-2000');?>" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M12 12m-4 0a4 4 0 1 0 8 0a4 4 0 1 0 -8 0" /><path d="M3 12h1m8 -9v1m8 8h1m-9 8v1m-6.4 -15.4l.7 .7m12.1 -.7l-.7 .7m0 11.4l.7 .7m-12.1 -.7l-.7 .7" /></svg>
              </a>
            </div>
            <div class="nav-item dropdown">
              <a  class="nav-link d-flex lh-1 text-reset p-0" data-bs-toggle="dropdown" aria-label="Open user menu">
                <span class="avatar avatar-sm">
                    <svg xmlns="<?php print_external('icon-2000');?>" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M8 7a4 4 0 1 0 8 0a4 4 0 0 0 -8 0"></path><path d="M6 21v-2a4 4 0 0 1 4 -4h4a4 4 0 0 1 4 4v2"></path></svg>
                </span>
                <div class="d-none d-xl-block ps-2">
                  <div><?php echo $_SESSION[FM_SESSION_ID]['logged'];?></div>
                </div>
              </a>
              <div class="dropdown-menu dropdown-menu-end dropdown-menu-arrow">
                <a href="" class="dropdown-item"><?php echo lng('Settings') ?></a>
                <a href="?logout=1" class="dropdown-item"><?php echo lng('Logout') ?></a>
              </div>
            </div>
          </div>
        </div>
        </header>
        <header class="navbar-expand-md">
        <div class="collapse navbar-collapse" id="navbar-menu">
          <div class="navbar">
            <div class="container-xl">
              <ul class="navbar-nav">
                <li class="nav-item nav-item-n <?php echo $nav=='home'?'active':'';?>">
                  <a class="nav-link" href="?p=" >
                    <span class="nav-link-icon d-md-none d-lg-inline-block">
                      <svg xmlns="<?php print_external('icon-2000');?>" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M5 12l-2 0l9 -9l9 9l-2 0" /><path d="M5 12v7a2 2 0 0 0 2 2h10a2 2 0 0 0 2 -2v-7" /><path d="M9 21v-6a2 2 0 0 1 2 -2h2a2 2 0 0 1 2 2v6" /></svg>
                    </span>
                    <span class="nav-link-title">
                    <?php echo lng('Home');?>
                    </span>
                  </a>
                </li>
                <li class="nav-item nav-item-n <?php echo $nav=='users'?'active':'';?>">
                  <a class="nav-link" href="?nav=users" >
                    <span class="nav-link-icon d-md-none d-lg-inline-block">
                    <svg xmlns="<?php print_external('icon-2000');?>" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M9 7m-4 0a4 4 0 1 0 8 0a4 4 0 1 0 -8 0"></path><path d="M3 21v-2a4 4 0 0 1 4 -4h4a4 4 0 0 1 4 4v2"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path><path d="M21 21v-2a4 4 0 0 0 -3 -3.85"></path></svg>
                    </span>
                    <span class="nav-link-title">
                      <?php echo lng('Users');?>
                    </span>
                  </a>
                </li>
                <li class="nav-item nav-item-n <?php echo $nav=='logs'?'active':'';?>">
                  <a class="nav-link" href="?nav=logs" >
                    <span class="nav-link-icon d-md-none d-lg-inline-block">
                        <svg xmlns="<?php print_external('icon-2000');?>" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M10 19h-6a1 1 0 0 1 -1 -1v-14a1 1 0 0 1 1 -1h6a2 2 0 0 1 2 2a2 2 0 0 1 2 -2h6a1 1 0 0 1 1 1v14a1 1 0 0 1 -1 1h-6a2 2 0 0 0 -2 2a2 2 0 0 0 -2 -2z"></path><path d="M12 5v16"></path><path d="M7 7h1"></path><path d="M7 11h1"></path><path d="M16 7h1"></path><path d="M16 11h1"></path><path d="M16 15h1"></path></svg>
                    </span>
                    <span class="nav-link-title">
                      <?php echo lng('Logs');?>
                    </span>
                  </a>
                </li>
                <li class="nav-item  nav-item-n <?php echo $nav=='settings'?'active':'';?>">
                  <a class="nav-link" href="?nav=settings" >
                    <span class="nav-link-icon d-md-none d-lg-inline-block">
                        <svg xmlns="<?php print_external('icon-2000');?>" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M10.325 4.317c.426 -1.756 2.924 -1.756 3.35 0a1.724 1.724 0 0 0 2.573 1.066c1.543 -.94 3.31 .826 2.37 2.37a1.724 1.724 0 0 0 1.065 2.572c1.756 .426 1.756 2.924 0 3.35a1.724 1.724 0 0 0 -1.066 2.573c.94 1.543 -.826 3.31 -2.37 2.37a1.724 1.724 0 0 0 -2.572 1.065c-.426 1.756 -2.924 1.756 -3.35 0a1.724 1.724 0 0 0 -2.573 -1.066c-1.543 .94 -3.31 -.826 -2.37 -2.37a1.724 1.724 0 0 0 -1.065 -2.572c-1.756 -.426 -1.756 -2.924 0 -3.35a1.724 1.724 0 0 0 1.066 -2.573c-.94 -1.543 .826 -3.31 2.37 -2.37c1 .608 2.296 .07 2.572 -1.065z"></path><path d="M9 12a3 3 0 1 0 6 0a3 3 0 0 0 -6 0"></path></svg>
                    </span>
                    <span class="nav-link-title">
                      <?php echo lng('Settings');?>
                    </span>
                  </a>
                </li>
              </ul>
              <div class="my-2 my-md-0 flex-grow-1 flex-md-grow-0 order-first order-md-last">
                <form id="search_form" action="" method="get" autocomplete="off" novalidate>
                  <div class="input-icon">
                    <span class="input-icon-addon">
                      <!-- Download SVG icon from http://tabler-icons.io/i/search -->
                      <svg xmlns="<?php print_external('icon-2000');?>" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M10 10m-7 0a7 7 0 1 0 14 0a7 7 0 1 0 -14 0" /><path d="M21 21l-6 -6" /></svg>
                    </span>
                    <input type="hidden" name="type" value="search">
                    <input type="hidden" name="path" value="<?php echo $path2 = $path ? $path : '.'; ?>">
                    <input type="text" id="search-value" onkeyup="filterFunction()" name="content"  value="" class="form-control fuzzy-search" placeholder="Search…" aria-label="Search in website">
                  </div>
                </form>

              </div>
            </div>
          </div>
        </div>
        </header>

<?php
}

/**
 * Show page footer after login
 */
function fm_show_footer()
{
    ?>
        </div>
    </div>
    <!-- Libs JS -->
    <?php print_external('js-dropzone');?>
    <?php print_external('js-list');?>
    <!-- Tabler Core -->
    <?php print_external('js-tabler');?>
    <?php print_external('js');?>
    <?php print_external('js-jquery');?>
    <?php print_external('js-toastr');?>
    <?php print_external('js-bootstrap');?>
    <script>
        var is_first="<?php echo isset($_SESSION[FM_SESSION_ID]['is_first'])?$_SESSION[FM_SESSION_ID]['is_first']:0;?>";
        function toast(type,txt) {console.log(type); if(type=='success'){toastr.success(txt);} else if(type=='error'){toastr.error(txt);}else if(type=='alert'){toastr.warning(txt);}else{toastr.info(txt);} }
        function rename(e, t) { if(t) { $("#js-rename-from").val(t);$("#js-rename-to").val(t); $("#modal-rename").modal('show'); } }
        function change_checkboxes(e, t) { for (var n = e.length - 1; n >= 0; n--) e[n].checked = "boolean" == typeof t ? t : !e[n].checked }
        function get_checkboxes(name) { if(name==''){name="file[]";} for (var e = document.getElementsByName(name), t = [], n = e.length - 1; n >= 0; n--) (e[n].type = "checkbox") && t.push(e[n]); return t }
        function select_all() { change_checkboxes(get_checkboxes(name), !0) }
        function unselect_all() { change_checkboxes(get_checkboxes(name), !1) }
        function invert_all() { change_checkboxes(get_checkboxes(name)) }
        function checkbox_toggle(name='') { var e = get_checkboxes(name); e.push(this), change_checkboxes(e) }
        function copy(p,n,g,t){
            var checkedValues = [];
            var content='';
            if(t==1){
                //批量
                $('input[type=checkbox]:checked').each(function(){
                    checkedValues.push({ id: this.value });
                    if(content==''){
                        content+=this.value;
                    }else{
                        content+=', '+this.value;
                    }
                });
            }else{
                content=n;
                checkedValues.push({ id: n });
            }
            
            $("#copy-file-form input[name=file]").val(JSON.stringify(checkedValues));
            $("#copy-file-form #file-name").val(content);
            $("#copy-file-form #old-folder").val(p+'/');
            $("#copy-file-form #path-folder").html(p+'/');
            $("#modal-copy").modal('show');
        }

        function unzip(p,n,g){
            $("#unzip-form #file-name").val(n);
            $("#unzip-form input[name=unzip]").val(n);
            $("#unzip-form #path-folder").html(p+'/');
            $("#unzip-modal").modal('show');
        }

        function pack(c, t) {
            var checkedValues = [];
            $('input[type=checkbox]:checked').each(function(){
                checkedValues.push({ id: this.value });
            });
            console.log('选中：'+JSON.stringify(checkedValues));
            $("#pack-form input[name=file]").val(JSON.stringify(checkedValues));
            console.log(t);
            if(t=='delete'){
                $("#modal-pack .modal-dialog").addClass('modal-sm');
                $("#modal-pack .modal-dialog").removeClass('modal-lg');
                $(".delete-div").show();
                $(".other-div").hide();
            }else{
                $("#modal-pack .modal-dialog").removeClass('modal-sm');
                $("#modal-pack .modal-dialog").addClass('modal-lg');
                $(".delete-div").hide();
                $(".other-div").show();
            }
            $(".pack-content").html(c+'<input type="hidden" name="'+t+'" value="'+t+'">');
            $("#modal-pack").modal('show');
        }

        function filterFunction() {
            var s_flag=true;
            if(!s_flag){
                toast('alert','请稍后');
                return false;
            }
            s_flag=false;

            var input, filter, tr,td, i,k, txtValue;
            input = document.getElementById('search-value');
            filter = input.value.toUpperCase();
            console.log("搜索关键词："+filter);
            div = document.getElementById("table-default");
            tr = div.getElementsByTagName('tr');
            
            for (i = 0; i < tr.length; i++) {
                td = tr[i].getElementsByTagName('td');
                var flag=1;
                if(td.length==6){
                    for(k = 1; k < 2; k++){
                        if(k==1){
                            txtValue = td[k].querySelector('a').textContent.toUpperCase() || td[k].querySelector('a').innerText.toUpperCase();
                        }else{
                            txtValue = td[k].textContent.toUpperCase() || td[k].innerText.toUpperCase();
                        }
                        if(txtValue=='..'){
                            break;
                        }else{
                            if (txtValue.indexOf(filter) == -1){
                                flag=0;
                                break;
                            }
                        }
                    }
                    
                    if(flag==0){
                        tr[i].style.display = "none";
                    }else{
                        tr[i].style.display = "";
                    }
                    flag=1;
                }
            }
            s_flag=true;
        }

        var myOffcanvas = document.getElementById('offcanvas')
        //详情显示
        myOffcanvas.addEventListener('show.bs.offcanvas', function (event) {
            var modal = $(this);  //get modal itself
            var a = $(event.relatedTarget);
            console.log(a.data('name'));
            var name=a.data('name');
            var url=window.location+'&detail='+name;
            console.log(url);
            $.ajax({
                type: "POST",
                url: url,
                data: '',
                cache: false,
                contentType: false,
                processData: false,
                success: function(mes){
                    mes=JSON.parse(mes);
                    $("#detail-name").html(mes.name);
                    $("#detail-size").html(mes.size);
                    $("#detail-ext").html(mes.ext);
                    $("#detail-date").html(mes.date);
                    $("#offcanvas-content").html(mes.html);
                },
                failure: function(mes) {toast('error',"Error: try again");},
                error: function(mes) {toast('error',mes.responseText);}
            });
        })

        //详情关闭
        myOffcanvas.addEventListener('hide.bs.offcanvas', function () {
            // 在这里执行你的自定义操作
            console.log('关闭来了');
            if($('#myVideo').length>0){
                console.log('视频页面');
                var video = $('#myVideo').get(0); // 转换为原生DOM对象
                video.pause();
            }
        })

        document.addEventListener("DOMContentLoaded", function() {
            const list = new List('table-default', {
                sortClass: 'table-sort',
                listClass: 'table-tbody',
                valueNames: [ 'sort-name', 'sort-size', 'sort-type',{ attr: 'data-date', name: 'sort-date' }]
            });

            const list1 = new List('table-default-users', {
                sortClass: 'table-sort',
                listClass: 'table-tbody',
                valueNames: [ 'sort-name', 'sort-email', 'sort-type',{ attr: 'data-date', name: 'sort-date' }]
            });
        })

        //上传弹框关闭
        var uploadmodal=document.getElementById('modal-upload');
        uploadmodal.addEventListener('hide.bs.modal', function () {
            //当前页面刷新
            console.log('关闭来了');
            window.location.reload();
        })

        //提示弹框加载
        toastr.options.positionClass = 'toast-top-center';

        //确认弹框显示
        $('#confirmDailog-modal').on('show.bs.modal', function (event) {
            var modal = $(this);  //get modal itself
            var a = $(event.relatedTarget)
            console.log(a.data('url'));
            if(a.data('action')=='delete'){
                modal.find('.modal-content #confirmDailog-form').attr('novalidate',true);
                modal.find('.modal-content #confirmDailog-form').attr('data-type','delete');
            }else{
                modal.find('.modal-content #confirmDailog-form').attr('novalidate',false);
                modal.find('.modal-content #confirmDailog-form').attr('data-type','download');
            }
            modal.find('.modal-content #confirmDailog-form').attr('action',a.data('url'));
            modal.find('.modal-body .modal-content-t').html(a.data('title')+' '+a.data('name'));
        });

        //确认删除用户
        $('#confirmDailog-user-modal').on('show.bs.modal', function (event) {
            var modal = $(this);  //get modal itself
            var a = $(event.relatedTarget)
            console.log(a.data('url'));
            if(a.data('action')=='delete'){
                modal.find('.modal-content #confirmDailog-user-form').attr('novalidate',true);
                modal.find('.modal-content #confirmDailog-user-form').attr('data-type','delete');
            }

            modal.find('.modal-content #confirmDailog-user-form').attr('action',a.data('url'));
            modal.find('.modal-body .modal-content-t').html(a.data('title')+' '+a.data('name'));
        });

        function edit(type,title,hash){
            var url=window.location+'&detail='+hash;
            $("#create-user-form").get(0).reset();
            $("#modal-users  .modal-title").html(title);
            if(type=='edit'){
                $.ajax({
                    type: "POST",
                    url: url,
                    data: '',
                    cache: false,
                    contentType: false,
                    processData: false,
                    success: function(mes){
                        mes=JSON.parse(mes);
                        $("#create-user-form input[name=user_hash]").val(hash);
                        $("#create-user-form input[name=name]").val(mes.info.name);
                        $("#create-user-form input[name=email]").val(mes.info.email);
                        $("#create-user-form input[name=path]").val(mes.info.path).attr('readOnly',true);
                        $("#create-user-form select[name=type]").val(mes.info.type);
                        $("#create-user-form select[name=delete_perm]").val(mes.info.delete_perm);
                        $("#modal-users").modal('show');
                    },
                    failure: function(mes) {toast('error',"Error: try again");},
                    error: function(mes) {toast('error',mes.responseText);}
                });
            }else{
                $("#modal-users").modal('show');
            }
        }

        //文件上传加载
        Dropzone.options.fileUploader = {
            chunking: true,//分片上传
            chunkSize: <?php echo UPLOAD_CHUNK_SIZE; ?>,//分片上传大小
            timeout: 120000,
            maxFilesize: <?php echo MAX_UPLOAD_SIZE; ?>,
            acceptedFiles : "<?php echo getUploadExt() ?>",
            init: function () {
                this.on("sending", function (file, xhr, formData) {
                    let _path = (file.fullPath) ? file.fullPath : file.name;
                    document.getElementById("fullpath").value = _path;
                    xhr.ontimeout = (function() {
                        toast('error','Error: Server Timeout');
                    });
                }).on("success", function (res) {
                    let _response = JSON.parse(res.xhr.response);
                    console.log(_response);
                    if(_response.status == "error") {
                        toast(_response.status,_response.info);
                    }
                }).on("error", function(file, response) {
                    toast("error",response);
                });
            }
        };

        $(document).ready( function () {
            if(is_first==1){
                $("#modal-password").modal('show');
            }

            // dataTable init
            /* $('#table-list-users').DataTable({
                searching: false, // 设置为 false 不加载搜索输入框
                bLengthChange:false,
            }); */

            if($("#col-images").length!=0){
                $(".col-images .text-muted").html($("#col-images").val());
                $(".col-videos .text-muted").html($("#col-videos").val());
                $(".col-documents .text-muted").html($("#col-documents").val());
                $(".col-other .text-muted").html($("#col-other").val());
            }

            //文件打包提交
            $("#pack-form").on('submit',function(e){
                e.preventDefault();
                var form = new FormData($(this)[0]);
                $.ajax({
                    type: "POST",
                    url: window.location,
                    data: form,
                    cache: false,
                    contentType: false,
                    processData: false,
                    success: function(mes){mes=JSON.parse(mes); toast(mes.status,mes.info); if(mes.status=='success'){window.location.reload();}},
                    failure: function(mes) {toast('error',"Error: try again");},
                    error: function(mes) {toast('error',mes.responseText);}
                });
            });

            //提醒【删除】提交
            $("#confirmDailog-form").on('submit',function(e){
                console.log($("#confirmDailog-form").attr('data-type'));
                if($("#confirmDailog-form").attr('data-type')=='delete'){
                    e.preventDefault();
                    var form = new FormData($(this)[0]);
                    var url=$("#confirmDailog-form").attr('action');
                    $.ajax({
                        type: "POST",
                        url: url,
                        data: form,
                        cache: false,
                        contentType: false,
                        processData: false,
                        success: function(mes){mes=JSON.parse(mes); toast(mes.status,mes.info); if(mes.status=='success'){window.location.reload();}},
                        failure: function(mes) {toast('error',"Error: try again");},
                        error: function(mes) {toast('error',mes.responseText);}
                    });
                }
            });

            //重命名 提交
            $("#rename_form").on('submit',function(e){
                e.preventDefault();
                var form = new FormData($(this)[0]);
                $.ajax({
                    type: "POST",
                    url: window.location,
                    data: form,
                    cache: false,
                    contentType: false,
                    processData: false,
                    success: function(mes){mes=JSON.parse(mes); toast(mes.status,mes.info); if(mes.status=='success'){window.location.reload();}},
                    failure: function(mes) {toast('error',"Error: try again");},
                    error: function(mes) {toast('error',mes.responseText);}
                });
            });

            //创建文件夹 提交
            $("#create-folder-form").on('submit',function(e){
                e.preventDefault();
                var form = new FormData($(this)[0]);
                $.ajax({
                    type: "POST",
                    url: window.location,
                    data: form,
                    cache: false,
                    contentType: false,
                    processData: false,
                    success: function(mes){mes=JSON.parse(mes); toast(mes.status,mes.info); if(mes.status=='success'){window.location.reload();}},
                    failure: function(mes) {toast('error',"Error: try again");},
                    error: function(mes) {toast('error',mes.responseText);}
                });
            });

            //复制和移动 提交
            $("#copy-file-form").on('submit',function(e){
                e.preventDefault();
                var form = new FormData($(this)[0]);
                $.ajax({
                    type: "POST",
                    url: window.location,
                    data: form,
                    cache: false,
                    contentType: false,
                    processData: false,
                    success: function(mes){mes=JSON.parse(mes); toast(mes.status,mes.info); if(mes.status=='success'){window.location.reload();}},
                    failure: function(mes) {toast('error',"Error: try again");},
                    error: function(mes) {toast('error',mes.responseText);}
                });
            });

            //添加用户
            $("#create-user-form").on('submit',function(e){
                e.preventDefault();
                var form = new FormData($(this)[0]);
                $.ajax({
                    type: "POST",
                    url: window.location,
                    data: form,
                    cache: false,
                    contentType: false,
                    processData: false,
                    success: function(mes){mes=JSON.parse(mes); toast(mes.status,mes.info); if(mes.status=='success'){window.location.reload();}},
                    failure: function(mes) {toast('error',"Error: try again");},
                    error: function(mes) {toast('error',mes.responseText);}
                });
            });

            //修改密码
            $("#change-password-form").on('submit',function(e){
                e.preventDefault();
                var form = new FormData($(this)[0]);
                $.ajax({
                    type: "POST",
                    url: window.location,
                    data: form,
                    cache: false,
                    contentType: false,
                    processData: false,
                    success: function(mes){mes=JSON.parse(mes); toast(mes.status,mes.info); if(mes.status=='success'){window.location.reload();}},
                    failure: function(mes) {toast('error',"Error: try again");},
                    error: function(mes) {toast('error',mes.responseText);}
                });
            });

            //提醒【删除用户】提交
            $("#confirmDailog-user-form").on('submit',function(e){
                e.preventDefault();
                var form = new FormData($(this)[0]);
                var url=$("#confirmDailog-user-form").attr('action');
                $.ajax({
                    type: "POST",
                    url: url,
                    data: form,
                    cache: false,
                    contentType: false,
                    processData: false,
                    success: function(mes){mes=JSON.parse(mes); toast(mes.status,mes.info); if(mes.status=='success'){window.location.reload();}},
                    failure: function(mes) {toast('error',"Error: try again");},
                    error: function(mes) {toast('error',mes.responseText);}
                });
            });
            //解压缩 提交
            $("#unzip-form").on('submit',function(e){
                e.preventDefault();
                var form = new FormData($(this)[0]);
                $.ajax({
                    type: "POST",
                    url: window.location,
                    data: form,
                    cache: false,
                    contentType: false,
                    processData: false,
                    success: function(mes){mes=JSON.parse(mes); toast(mes.status,mes.info); if(mes.status=='success'){window.location.reload();}},
                    failure: function(mes) {toast('error',"Error: try again");},
                    error: function(mes) {toast('error',mes.responseText);}
                });
            });
        });

    </script>
  </body>
</html>

<?php
}

function fm_show_users(){

}

function getUploadExt() {
    $extArr = explode(',', FM_UPLOAD_EXTENSION);
    if(FM_UPLOAD_EXTENSION && $extArr) {
        array_walk($extArr, function(&$x) {$x = ".$x";});
        return implode(',', $extArr);
    }
    return '';
}

/**
 * Safely create folder
 * @param string $dir
 * @param bool $force
 * @return bool
 */
function fm_mkdir($dir, $force)
{
    if (file_exists($dir)) {
        if (is_dir($dir)) {
            return $dir;
        } elseif (!$force) {
            return false;
        }
        unlink($dir);
    }
    return mkdir($dir, 0777, true);
}

/**
 * Get mime type
 * @param string $file_path
 * @return mixed|string
 */
function fm_get_mime_type($file_path)
{
    if (function_exists('finfo_open')) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = finfo_file($finfo, $file_path);
        finfo_close($finfo);
        return $mime;
    } elseif (function_exists('mime_content_type')) {
        return mime_content_type($file_path);
    } elseif (!stristr(ini_get('disable_functions'), 'shell_exec')) {
        $file = escapeshellarg($file_path);
        $mime = shell_exec('file -bi ' . $file);
        return $mime;
    } else {
        return '--';
    }
}

/**
 * HTTP Redirect
 * @param string $url
 * @param int $code
 */
function fm_redirect($url, $code = 302)
{
    header('Location: ' . $url, true, $code);
    exit;
}

/**
 * Verify CSRF TOKEN and remove after cerify
 * @param string $token
 * @return bool
 */
function verifyToken($token) 
{
    if (hash_equals($_SESSION['token'], $token)) { 
        return true;
    }
    return false;
}

/**
 * Delete  file or folder (recursively)
 * @param string $path
 * @return bool
 */
function fm_rdelete($path)
{
    if (is_link($path)) {
        return unlink($path);
    } elseif (is_dir($path)) {
        $objects = scandir($path);
        $ok = true;
        if (is_array($objects)) {
            foreach ($objects as $file) {
                if ($file != '.' && $file != '..') {
                    if (!fm_rdelete($path . '/' . $file)) {
                        $ok = false;
                    }
                }
            }
        }
        return ($ok) ? rmdir($path) : false;
    } elseif (is_file($path)) {
        return unlink($path);
    }
    return false;
}

/**
 * Check the file extension which is allowed or not
 * @param string $filename
 * @return bool
 */
function fm_is_valid_ext($filename)
{
    $allowed = (FM_FILE_EXTENSION) ? explode(',', FM_FILE_EXTENSION) : false;

    $ext = pathinfo($filename, PATHINFO_EXTENSION);
    $isFileAllowed = ($allowed) ? in_array($ext, $allowed) : true;

    return ($isFileAllowed) ? true : false;
}

/**
 * Safely rename
 * @param string $old
 * @param string $new
 * @return bool|null
 */
function fm_rename($old, $new)
{
    $isFileAllowed = fm_is_valid_ext($new);

    if(!is_dir($old)) {
        if (!$isFileAllowed) return false;
    }

    return (!file_exists($new) && file_exists($old)) ? rename($old, $new) : null;
}

/**
 * Copy file or folder (recursively).
 * @param string $path
 * @param string $dest
 * @param bool $upd Update files
 * @param bool $force Create folder with same names instead file
 * @return bool
 */
function fm_rcopy($path, $dest, $upd = true, $force = true)
{
    if (is_dir($path)) {
        if (!fm_mkdir($dest, $force)) {
            return false;
        }
        $objects = scandir($path);
        $ok = true;
        if (is_array($objects)) {
            foreach ($objects as $file) {
                if ($file != '.' && $file != '..') {
                    if (!fm_rcopy($path . '/' . $file, $dest . '/' . $file)) {
                        $ok = false;
                    }
                }
            }
        }
        return $ok;
    } elseif (is_file($path)) {
        return fm_copy($path, $dest, $upd);
    }
    return false;
}

/**
 * Safely copy file
 * @param string $f1
 * @param string $f2
 * @param bool $upd Indicates if file should be updated with new content
 * @return bool
 */
function fm_copy($f1, $f2, $upd)
{
    $time1 = filemtime($f1);
    if (file_exists($f2)) {
        $time2 = filemtime($f2);
        if ($time2 >= $time1 && $upd) {
            return false;
        }
    }
    $ok = copy($f1, $f2);
    if ($ok) {
        touch($f2, $time1);
    }
    return $ok;
}

/**
 * Path traversal prevention and clean the url
 * It replaces (consecutive) occurrences of / and \\ with whatever is in DIRECTORY_SEPARATOR, and processes /. and /.. fine.
 * @param $path
 * @return string
 */
function get_absolute_path($path)
{
    $path = str_replace(array('/', '\\'), DIRECTORY_SEPARATOR, $path);
    $parts = array_filter(explode(DIRECTORY_SEPARATOR, $path), 'strlen');
    $absolutes = array();
    foreach ($parts as $part) {
        if ('.' == $part) {
            continue;
        }

        if ('..' == $part) {
            array_pop($absolutes);
        } else {
            $absolutes[] = $part;
        }
    }
    return implode(DIRECTORY_SEPARATOR, $absolutes);
}

/**
 * Clean path
 * @param string $path
 * @return string
 */
function fm_clean_path($path, $trim = true)
{
    $path = $trim ? trim($path) : $path;
    $path = trim($path, '\\/');
    $path = str_replace(array('../', '..\\'), '', $path);
    $path = get_absolute_path($path);
    if ($path == '..') {
        $path = '';
    }
    return str_replace('\\', '/', $path);
}

/**
 * Get parent path
 * @param string $path
 * @return bool|string
 */
function fm_get_parent_path($path)
{
    $path = fm_clean_path($path);
    if ($path != '') {
        $array = explode('/', $path);
        if (count($array) > 1) {
            $array = array_slice($array, 0, -1);
            return implode('/', $array);
        }
        return '';
    }
    return false;
}

/**
* Parameters: downloadFile(File Location, File Name,
* max speed, is streaming
* If streaming - videos will show as videos, images as images
* instead of download prompt
* https://stackoverflow.com/a/13821992/1164642
*/
function fm_download_file($fileLocation, $fileName, $chunkSize  = 1024)
{
    if (connection_status() != 0)
        return (false);
    $extension = pathinfo($fileName, PATHINFO_EXTENSION);

    $contentType = fm_get_file_mimes($extension);

    if(is_array($contentType)) {
        $contentType = implode(' ', $contentType);
    }

    $size = filesize($fileLocation);

    if ($size == 0) {
        fm_set_msg(lng('Zero byte file! Aborting download'), 'error');
        $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));

        return (false);
    }

    @ini_set('magic_quotes_runtime', 0);
    $fp = fopen("$fileLocation", "rb");

    if ($fp === false) {
        fm_set_msg(lng('Cannot open file! Aborting download'), 'error');
        $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
        return (false);
    }

    // headers
    header('Content-Description: File Transfer');
    header('Expires: 0');
    header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
    header('Pragma: public');
    header("Content-Transfer-Encoding: binary");
    header("Content-Type: $contentType");

    $contentDisposition = 'attachment';

    if (strstr($_SERVER['HTTP_USER_AGENT'], "MSIE")) {
        $fileName = preg_replace('/\./', '%2e', $fileName, substr_count($fileName, '.') - 1);
        header("Content-Disposition: $contentDisposition;filename=\"$fileName\"");
    } else {
        header("Content-Disposition: $contentDisposition;filename=\"$fileName\"");
    }

    header("Accept-Ranges: bytes");
    $range = 0;

    if (isset($_SERVER['HTTP_RANGE'])) {
        list($a, $range) = explode("=", $_SERVER['HTTP_RANGE']);
        str_replace($range, "-", $range);
        $size2 = $size - 1;
        $new_length = $size - $range;
        header("HTTP/1.1 206 Partial Content");
        header("Content-Length: $new_length");
        header("Content-Range: bytes $range$size2/$size");
    } else {
        $size2 = $size - 1;
        header("Content-Range: bytes 0-$size2/$size");
        header("Content-Length: " . $size);
    }
    $fileLocation = realpath($fileLocation);
    while (ob_get_level()) ob_end_clean();
    readfile($fileLocation);

    fclose($fp);

    return ((connection_status() == 0) and !connection_aborted());
}

/**
 * If the theme is dark, return the text-white and bg-dark classes.
 * @return string the value of the  variable.
 */
function fm_get_theme()
{
    $result = '';
    if (FM_THEME == "dark") {
        $result = "dark";
    }
    return $result;
}

/**
 * 获取相关文件夹
 */
function get_folders($path){
    $objects = is_readable($path) ? scandir($path) : array();
    $folders = array();
    $current_path = array_slice(explode("/", $path), -1)[0];
    $i=0;
    if (is_array($objects) && fm_is_exclude_items($current_path)) {
        foreach ($objects as $file) {
            if ($file == '.' || $file == '..') {
                continue;
            }
            if (!FM_SHOW_HIDDEN && substr($file, 0, 1) === '.') {
                continue;
            }
            $new_path = $path . '/' . $file;
            if (@is_file($new_path) && fm_is_exclude_items($file)) {
                continue;
            } elseif (@is_dir($new_path) && $file != '.' && $file != '..' && fm_is_exclude_items($file)) {
                $folders[$i]['path'] = $path;
                $folders[$i]['name'] = $file;
                $lists=get_folders($new_path);
                $folders[$i]['list'] = empty($lists)?null:$lists;
            }
            $i++;
        }
    }

    return $folders;
}

/**
 * Class to work with zip files (using ZipArchive)
 */
class FM_Zipper
{
    private $zip;

    public function __construct()
    {
        $this->zip = new ZipArchive();
    }

    /**
     * Create archive with name $filename and files $files (RELATIVE PATHS!)
     * @param string $filename
     * @param array|string $files
     * @return bool
     */
    public function create($filename, $files)
    {
        $res = $this->zip->open($filename, ZipArchive::CREATE);
        if ($res !== true) {
            return false;
        }
        if (is_array($files)) {
            foreach ($files as $f) {
                $f = fm_clean_path($f);
                if (!$this->addFileOrDir($f)) {
                    $this->zip->close();
                    return false;
                }
            }
            $this->zip->close();
            return true;
        } else {
            if ($this->addFileOrDir($files)) {
                $this->zip->close();
                return true;
            }
            return false;
        }
    }

    /**
     * Extract archive $filename to folder $path (RELATIVE OR ABSOLUTE PATHS)
     * @param string $filename
     * @param string $path
     * @return bool
     */
    public function unzip($filename, $path)
    {
        $res = $this->zip->open($filename);
        if ($res !== true) {
            return false;
        }
        if ($this->zip->extractTo($path)) {
            $this->zip->close();
            return true;
        }
        return false;
    }

    /**
     * Add file/folder to archive
     * @param string $filename
     * @return bool
     */
    private function addFileOrDir($filename)
    {
        if (is_file($filename)) {
            return $this->zip->addFile($filename);
        } elseif (is_dir($filename)) {
            return $this->addDir($filename);
        }
        return false;
    }

    /**
     * Add folder recursively
     * @param string $path
     * @return bool
     */
    private function addDir($path)
    {
        if (!$this->zip->addEmptyDir($path)) {
            return false;
        }
        $objects = scandir($path);
        if (is_array($objects)) {
            foreach ($objects as $file) {
                if ($file != '.' && $file != '..') {
                    if (is_dir($path . '/' . $file)) {
                        if (!$this->addDir($path . '/' . $file)) {
                            return false;
                        }
                    } elseif (is_file($path . '/' . $file)) {
                        if (!$this->zip->addFile($path . '/' . $file)) {
                            return false;
                        }
                    }
                }
            }
            return true;
        }
        return false;
    }
}

/**
 * Class to work with Tar files (using PharData)
 */
class FM_Zipper_Tar
{
    private $tar;

    public function __construct()
    {
        $this->tar = null;
    }

    /**
     * Create archive with name $filename and files $files (RELATIVE PATHS!)
     * @param string $filename
     * @param array|string $files
     * @return bool
     */
    public function create($filename, $files)
    {
        $this->tar = new PharData($filename);
        if (is_array($files)) {
            foreach ($files as $f) {
                $f = fm_clean_path($f);
                if (!$this->addFileOrDir($f)) {
                    return false;
                }
            }
            return true;
        } else {
            if ($this->addFileOrDir($files)) {
                return true;
            }
            return false;
        }
    }

    /**
     * Extract archive $filename to folder $path (RELATIVE OR ABSOLUTE PATHS)
     * @param string $filename
     * @param string $path
     * @return bool
     */
    public function unzip($filename, $path)
    {
        $res = $this->tar->open($filename);
        if ($res !== true) {
            return false;
        }
        if ($this->tar->extractTo($path)) {
            return true;
        }
        return false;
    }

    /**
     * Add file/folder to archive
     * @param string $filename
     * @return bool
     */
    private function addFileOrDir($filename)
    {
        if (is_file($filename)) {
            try {
                $this->tar->addFile($filename);
                return true;
            } catch (Exception $e) {
                return false;
            }
        } elseif (is_dir($filename)) {
            return $this->addDir($filename);
        }
        return false;
    }

    /**
     * Add folder recursively
     * @param string $path
     * @return bool
     */
    private function addDir($path)
    {
        $objects = scandir($path);
        if (is_array($objects)) {
            foreach ($objects as $file) {
                if ($file != '.' && $file != '..') {
                    if (is_dir($path . '/' . $file)) {
                        if (!$this->addDir($path . '/' . $file)) {
                            return false;
                        }
                    } elseif (is_file($path . '/' . $file)) {
                        try {
                            $this->tar->addFile($path . '/' . $file);
                        } catch (Exception $e) {
                            return false;
                        }
                    }
                }
            }
            return true;
        }
        return false;
    }
}

/**
 * Save message in session
 * @param string $msg
 * @param string $status
 */
function fm_set_msg($msg, $status = 'ok')
{
    $_SESSION[FM_SESSION_ID]['message'] = $msg;
    $_SESSION[FM_SESSION_ID]['status'] = $status;
}

/**
 * Check if string is in UTF-8
 * @param string $string
 * @return int
 */
function fm_is_utf8($string)
{
    return preg_match('//u', $string);
}

/**
 * Convert file name to UTF-8 in Windows
 * @param string $filename
 * @return string
 */
function fm_convert_win($filename)
{
    if (FM_IS_WIN && function_exists('iconv')) {
        $filename = iconv(FM_ICONV_INPUT_ENC, 'UTF-8//IGNORE', $filename);
    }
    return $filename;
}

/**
 * @param $obj
 * @return array
 */
function fm_object_to_array($obj)
{
    if (!is_object($obj) && !is_array($obj)) {
        return $obj;
    }
    if (is_object($obj)) {
        $obj = get_object_vars($obj);
    }
    return array_map('fm_object_to_array', $obj);
}

/**
 * Check file is in exclude list
 * @param string $file
 * @return bool
 */
function fm_is_exclude_items($file)
{
    $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
    if (isset($exclude_items) and sizeof($exclude_items)) {
        unset($exclude_items);
    }

    $exclude_items = FM_EXCLUDE_ITEMS;
    if (version_compare(PHP_VERSION, '7.0.0', '<')) {
        $exclude_items = unserialize($exclude_items);
    }
    if (!in_array($file, $exclude_items) && !in_array("*.$ext", $exclude_items)) {
        return true;
    }
    return false;
}

/**
 * get language translations from json file
 * @param int $tr
 * @return array
 */
function fm_get_translations($tr)
{
    try {
        $content = @file_get_contents('data/translation.json');
        if ($content !== false) {
            $lng = json_decode($content, true);
            global $lang_list;
            foreach ($lng["language"] as $key => $value) {
                $code = $value["code"];
                $lang_list[$code] = $value["name"];
                if ($tr) {
                    $tr[$code] = $value["translation"];
                }

            }
            return $tr;
        }

    } catch (Exception $e) {
        echo $e;
    }
}

/**
 * @param string $file
 * Recover all file sizes larger than > 2GB.
 * Works on php 32bits and 64bits and supports linux
 * @return int|string
 */
function fm_get_size($file)
{
    static $iswin;
    static $isdarwin;
    if (!isset($iswin)) {
        $iswin = (strtoupper(substr(PHP_OS, 0, 3)) == 'WIN');
    }
    if (!isset($isdarwin)) {
        $isdarwin = (strtoupper(substr(PHP_OS, 0)) == "DARWIN");
    }

    static $exec_works;
    if (!isset($exec_works)) {
        $exec_works = (function_exists('exec') && !ini_get('safe_mode') && @exec('echo EXEC') == 'EXEC');
    }

    // try a shell command
    if ($exec_works) {
        $arg = escapeshellarg($file);
        $cmd = ($iswin) ? "for %F in (\"$file\") do @echo %~zF" : ($isdarwin ? "stat -f%z $arg" : "stat -c%s $arg");
        @exec($cmd, $output);
        if (is_array($output) && ctype_digit($size = trim(implode("\n", $output)))) {
            return $size;
        }
    }

    // try the Windows COM interface
    if ($iswin && class_exists("COM")) {
        try {
            $fsobj = new COM('Scripting.FileSystemObject');
            $f = $fsobj->GetFile(realpath($file));
            $size = $f->Size;
        } catch (Exception $e) {
            $size = null;
        }
        if (ctype_digit($size)) {
            return $size;
        }
    }

    // if all else fails
    return filesize($file);
}

/**
 * Get nice filesize
 * @param int $size
 * @return string
 */
function fm_get_filesize($size)
{
    $size = (float) $size;
    $units = array('B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB');
    $power = ($size > 0) ? floor(log($size, 1024)) : 0;
    $power = ($power > (count($units) - 1)) ? (count($units) - 1) : $power;
    return sprintf('%s %s', round($size / pow(1024, $power), 2), $units[$power]);
}

/**
 * Get total size of directory tree.
 *
 * @param  string $directory Relative or absolute directory name.
 * @return int Total number of bytes.
 */
function fm_get_directorysize($directory)
{
    $bytes = 0;
    $directory = realpath($directory);
    if ($directory !== false && $directory != '' && file_exists($directory)) {
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS)) as $file) {
            $bytes += $file->getSize();
        }
    }
    return $bytes;
}

/**
 * Get CSS classname for file
 * @param string $path
 * @return string
 */
function fm_get_file_icon_class($path,$icon_url)
{
    // get extension
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));

    switch ($ext) {
        case 'ico':
        case 'gif':
        case 'jpg':
        case 'jpeg':
        case 'jpc':
        case 'jp2':
        case 'jpx':
        case 'xbm':
        case 'wbmp':
        case 'png':
        case 'bmp':
        case 'tif':
        case 'tiff':
        case 'webp':
        case 'avif':
        case 'svg':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-photo icon-green"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M15 8h.01"></path><path d="M3 6a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v12a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3v-12z"></path><path d="M3 16l5 -5c.928 -.893 2.072 -.893 3 0l5 5"></path><path d="M14 14l1 -1c.928 -.893 2.072 -.893 3 0l3 3"></path></svg>';
            break;
        case 'passwd':
        case 'ftpquota':
        case 'sql':
        case 'js':
        case 'ts':
        case 'jsx':
        case 'tsx':
        case 'hbs':
        case 'json':
        case 'sh':
        case 'config':
        case 'twig':
        case 'tpl':
        case 'md':
        case 'gitignore':
        case 'c':
        case 'cpp':
        case 'cs':
        case 'py':
        case 'rs':
        case 'map':
        case 'lock':
        case 'dtd':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-file-code icon-green"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M14 3v4a1 1 0 0 0 1 1h4"></path><path d="M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2z"></path><path d="M10 13l-1 2l1 2"></path><path d="M14 13l1 2l-1 2"></path></svg>';
            break;
        case 'txt':
        case 'ini':
        case 'conf':
        case 'log':
        case 'htaccess':
        case 'yaml':
        case 'yml':
        case 'toml':
        case 'tmp':
        case 'top':
        case 'bot':
        case 'dat':
        case 'bak':
        case 'htpasswd':
        case 'pl':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-file-text icon-green"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M14 3v4a1 1 0 0 0 1 1h4"></path><path d="M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2z"></path><path d="M9 9l1 0"></path><path d="M9 13l6 0"></path><path d="M9 17l6 0"></path></svg>';
            break;
        case 'css':
        case 'less':
        case 'sass':
        case 'scss':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-file-type-css icon-green"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M14 3v4a1 1 0 0 0 1 1h4"></path><path d="M5 12v-7a2 2 0 0 1 2 -2h7l5 5v4"></path><path d="M8 16.5a1.5 1.5 0 0 0 -3 0v3a1.5 1.5 0 0 0 3 0"></path><path d="M11 20.25c0 .414 .336 .75 .75 .75h1.25a1 1 0 0 0 1 -1v-1a1 1 0 0 0 -1 -1h-1a1 1 0 0 1 -1 -1v-1a1 1 0 0 1 1 -1h1.25a.75 .75 0 0 1 .75 .75"></path><path d="M17 20.25c0 .414 .336 .75 .75 .75h1.25a1 1 0 0 0 1 -1v-1a1 1 0 0 0 -1 -1h-1a1 1 0 0 1 -1 -1v-1a1 1 0 0 1 1 -1h1.25a.75 .75 0 0 1 .75 .75"></path></svg>';
            break;
        case 'bz2':
        case 'zip':
        case 'rar':
        case 'gz':
        case 'tar':
        case '7z':
        case 'xz':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-file-zip icon-red"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M6 20.735a2 2 0 0 1 -1 -1.735v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2h-1"></path><path d="M11 17a2 2 0 0 1 2 2v2a1 1 0 0 1 -1 1h-2a1 1 0 0 1 -1 -1v-2a2 2 0 0 1 2 -2z"></path><path d="M11 5l-1 0"></path><path d="M13 7l-1 0"></path><path d="M11 9l-1 0"></path><path d="M13 11l-1 0"></path><path d="M11 13l-1 0"></path><path d="M13 15l-1 0"></path></svg>';
            break;
        case 'php':
        case 'php4':
        case 'php5':
        case 'phps':
        case 'phtml':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-file-type-php icon-green"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M14 3v4a1 1 0 0 0 1 1h4"></path><path d="M5 12v-7a2 2 0 0 1 2 -2h7l5 5v4"></path><path d="M5 18h1.5a1.5 1.5 0 0 0 0 -3h-1.5v6"></path><path d="M17 18h1.5a1.5 1.5 0 0 0 0 -3h-1.5v6"></path><path d="M11 21v-6"></path><path d="M14 15v6"></path><path d="M11 18h3"></path></svg>';
            break;
        case 'htm':
        case 'html':
        case 'shtml':
        case 'xhtml':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-html icon-green"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M13 16v-8l2 5l2 -5v8"></path><path d="M1 16v-8"></path><path d="M5 8v8"></path><path d="M1 12h4"></path><path d="M7 8h4"></path><path d="M9 8v8"></path><path d="M20 8v8h3"></path></svg>';
            break;
        case 'xml':
        case 'xsl':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-file-type-xml icon-green"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M14 3v4a1 1 0 0 0 1 1h4"></path><path d="M5 12v-7a2 2 0 0 1 2 -2h7l5 5v4"></path><path d="M4 15l4 6"></path><path d="M4 21l4 -6"></path><path d="M19 15v6h3"></path><path d="M11 21v-6l2.5 3l2.5 -3v6"></path></svg>';
            break;
        case 'wav':
        case 'mp3':
        case 'mp2':
        case 'm4a':
        case 'aac':
        case 'ogg':
        case 'oga':
        case 'wma':
        case 'mka':
        case 'flac':
        case 'ac3':
        case 'tds':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-music icon-green"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M3 17a3 3 0 1 0 6 0a3 3 0 0 0 -6 0"></path><path d="M13 17a3 3 0 1 0 6 0a3 3 0 0 0 -6 0"></path><path d="M9 17v-13h10v13"></path><path d="M9 8h10"></path></svg>';
            break;
        case 'm3u':
        case 'm3u8':
        case 'pls':
        case 'cue':
        case 'xspf':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-headphones icon-green"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M4 13m0 2a2 2 0 0 1 2 -2h1a2 2 0 0 1 2 2v3a2 2 0 0 1 -2 2h-1a2 2 0 0 1 -2 -2z"></path><path d="M15 13m0 2a2 2 0 0 1 2 -2h1a2 2 0 0 1 2 2v3a2 2 0 0 1 -2 2h-1a2 2 0 0 1 -2 -2z"></path><path d="M4 15v-3a8 8 0 0 1 16 0v3"></path></svg>';
            break;
        case 'avi':
        case 'mpg':
        case 'mpeg':
        case 'mp4':
        case 'm4v':
        case 'flv':
        case 'f4v':
        case 'ogm':
        case 'ogv':
        case 'mov':
        case 'mkv':
        case '3gp':
        case 'asf':
        case 'wmv':
        case 'webm':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-video icon-green"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M15 10l4.553 -2.276a1 1 0 0 1 1.447 .894v6.764a1 1 0 0 1 -1.447 .894l-4.553 -2.276v-4z"></path><path d="M3 6m0 2a2 2 0 0 1 2 -2h8a2 2 0 0 1 2 2v8a2 2 0 0 1 -2 2h-8a2 2 0 0 1 -2 -2z"></path></svg>';
            break;
        case 'eml':
        case 'msg':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-mug icon-green"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M4.083 5h10.834a1.08 1.08 0 0 1 1.083 1.077v8.615c0 2.38 -1.94 4.308 -4.333 4.308h-4.334c-2.393 0 -4.333 -1.929 -4.333 -4.308v-8.615a1.08 1.08 0 0 1 1.083 -1.077"></path><path d="M16 8h2.5c1.38 0 2.5 1.045 2.5 2.333v2.334c0 1.288 -1.12 2.333 -2.5 2.333h-2.5"></path></svg>';
            break;
        case 'xls':
        case 'xlsx':
        case 'ods':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-file-type-xls icon-green"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M14 3v4a1 1 0 0 0 1 1h4"></path><path d="M5 12v-7a2 2 0 0 1 2 -2h7l5 5v4"></path><path d="M4 15l4 6"></path><path d="M4 21l4 -6"></path><path d="M17 20.25c0 .414 .336 .75 .75 .75h1.25a1 1 0 0 0 1 -1v-1a1 1 0 0 0 -1 -1h-1a1 1 0 0 1 -1 -1v-1a1 1 0 0 1 1 -1h1.25a.75 .75 0 0 1 .75 .75"></path><path d="M11 15v6h3"></path></svg>';
            break;
        case 'csv':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-file-type-csv icon-green"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M14 3v4a1 1 0 0 0 1 1h4"></path><path d="M5 12v-7a2 2 0 0 1 2 -2h7l5 5v4"></path><path d="M7 16.5a1.5 1.5 0 0 0 -3 0v3a1.5 1.5 0 0 0 3 0"></path><path d="M10 20.25c0 .414 .336 .75 .75 .75h1.25a1 1 0 0 0 1 -1v-1a1 1 0 0 0 -1 -1h-1a1 1 0 0 1 -1 -1v-1a1 1 0 0 1 1 -1h1.25a.75 .75 0 0 1 .75 .75"></path><path d="M16 15l2 6l2 -6"></path></svg>';
            break;
        case 'bak':
        case 'swp':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-file icon-green"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M14 3v4a1 1 0 0 0 1 1h4"></path><path d="M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2z"></path></svg>';
            break;
        case 'doc':
        case 'docx':
        case 'odt':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-file-type-doc icon-green"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M14 3v4a1 1 0 0 0 1 1h4"></path><path d="M5 12v-7a2 2 0 0 1 2 -2h7l5 5v4"></path><path d="M5 15v6h1a2 2 0 0 0 2 -2v-2a2 2 0 0 0 -2 -2h-1z"></path><path d="M20 16.5a1.5 1.5 0 0 0 -3 0v3a1.5 1.5 0 0 0 3 0"></path><path d="M12.5 15a1.5 1.5 0 0 1 1.5 1.5v3a1.5 1.5 0 0 1 -3 0v-3a1.5 1.5 0 0 1 1.5 -1.5z"></path></svg>';
            break;
        case 'ppt':
        case 'pptx':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-file-type-ppt icon-green"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M14 3v4a1 1 0 0 0 1 1h4"></path><path d="M14 3v4a1 1 0 0 0 1 1h4"></path><path d="M5 18h1.5a1.5 1.5 0 0 0 0 -3h-1.5v6"></path><path d="M11 18h1.5a1.5 1.5 0 0 0 0 -3h-1.5v6"></path><path d="M16.5 15h3"></path><path d="M18 15v6"></path><path d="M5 12v-7a2 2 0 0 1 2 -2h7l5 5v4"></path></svg>';
            break;
        case 'ttf':
        case 'ttc':
        case 'otf':
        case 'woff':
        case 'woff2':
        case 'eot':
        case 'fon':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-typography icon-green"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M4 20l3 0"></path><path d="M14 20l7 0"></path><path d="M6.9 15l6.9 0"></path><path d="M10.2 6.3l5.8 13.7"></path><path d="M5 20l6 -16l2 0l7 16"></path></svg>';
            break;
        case 'pdf':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-file-type-pdf icon-green"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M14 3v4a1 1 0 0 0 1 1h4"></path><path d="M5 12v-7a2 2 0 0 1 2 -2h7l5 5v4"></path><path d="M5 18h1.5a1.5 1.5 0 0 0 0 -3h-1.5v6"></path><path d="M17 18h2"></path><path d="M20 15h-3v6"></path><path d="M11 15v6h1a2 2 0 0 0 2 -2v-2a2 2 0 0 0 -2 -2h-1z"></path></svg>';
            break;
        case 'psd':
        case 'ai':
        case 'eps':
        case 'fla':
        case 'swf':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-photo-ai icon-green"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M15 8h.01"></path><path d="M10 21h-4a3 3 0 0 1 -3 -3v-12a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v5"></path><path d="M3 16l5 -5c.928 -.893 2.072 -.893 3 0l1 1"></path><path d="M14 21v-4a2 2 0 1 1 4 0v4"></path><path d="M14 19h4"></path><path d="M21 15v6"></path></svg>';
            break;
        case 'exe':
        case 'msi':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-file"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M14 3v4a1 1 0 0 0 1 1h4"></path><path d="M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2z"></path></svg>';
            break;
        case 'bat':
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-bat icon-green"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M17 16c.74 -2.286 2.778 -3.762 5 -3c-.173 -2.595 .13 -5.314 -2 -7.5c-1.708 2.648 -3.358 2.557 -5 2.5v-4l-3 2l-3 -2v4c-1.642 .057 -3.292 .148 -5 -2.5c-2.13 2.186 -1.827 4.905 -2 7.5c2.222 -.762 4.26 .714 5 3c2.593 0 3.889 .952 5 4c1.111 -3.048 2.407 -4 5 -4z"></path><path d="M9 8a3 3 0 0 0 6 0"></path></svg>';
            break;
        default:
            $img = '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-file-info icon-green"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M14 3v4a1 1 0 0 0 1 1h4"></path><path d="M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2z"></path><path d="M11 14h1v4h1"></path><path d="M12 11h.01"></path></svg>';
    }

    return $img;
}

function show_folder_icon($icon_url){
    return '<svg xmlns="'.$icon_url.'" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-folder icon-blue"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M5 4h4l3 3h7a2 2 0 0 1 2 2v8a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2v-11a2 2 0 0 1 2 -2"></path></svg>';
}

/**
 * Get image files extensions
 * @return array
 */
function fm_get_image_exts()
{
    return array('ico', 'gif', 'jpg', 'jpeg', 'jpc', 'jp2', 'jpx', 'xbm', 'wbmp', 'png', 'bmp', 'tif', 'tiff', 'psd', 'svg', 'webp', 'avif');
}

/**
 * Get video files extensions
 * @return array
 */
function fm_get_video_exts()
{
    return array('avi', 'webm', 'wmv', 'mp4', 'm4v', 'ogm', 'ogv', 'mov', 'mkv');
}

/**
 * Get audio files extensions
 * @return array
 */
function fm_get_audio_exts()
{
    return array('wav', 'mp3', 'ogg', 'm4a');
}

/**
 * Get text file extensions
 * @return array
 */
function fm_get_text_exts()
{
    return array(
        'txt', 'css', 'ini', 'conf', 'log', 'htaccess', 'passwd', 'ftpquota', 'sql', 'js', 'ts', 'jsx', 'tsx', 'mjs', 'json', 'sh', 'config',
        'php', 'php4', 'php5', 'phps', 'phtml', 'htm', 'html', 'shtml', 'xhtml', 'xml', 'xsl', 'm3u', 'm3u8', 'pls', 'cue', 'bash', 'vue',
        'eml', 'msg', 'csv', 'bat', 'twig', 'tpl', 'md', 'gitignore', 'less', 'sass', 'scss', 'c', 'cpp', 'cs', 'py', 'go', 'zsh', 'swift',
        'map', 'lock', 'dtd', 'svg', 'asp', 'aspx', 'asx', 'asmx', 'ashx', 'jsp', 'jspx', 'cgi', 'dockerfile', 'ruby', 'yml', 'yaml', 'toml',
        'vhost', 'scpt', 'applescript', 'csx', 'cshtml', 'c++', 'coffee', 'cfm', 'rb', 'graphql', 'mustache', 'jinja', 'http', 'handlebars',
        'java', 'es', 'es6', 'markdown', 'wiki', 'tmp', 'top', 'bot', 'dat', 'bak', 'htpasswd', 'pl'
    );
}

/**
 * Get mime types of text files
 * @return array
 */
function fm_get_text_mimes()
{
    return array(
        'application/xml',
        'application/javascript',
        'application/x-javascript',
        'image/svg+xml',
        'message/rfc822',
        'application/json',
    );
}

/**
 * Get file names of text files w/o extensions
 * @return array
 */
function fm_get_text_names()
{
    return array(
        'license',
        'readme',
        'authors',
        'contributors',
        'changelog',
    );
}

/**
 * Get online docs viewer supported files extensions
 * @return array
 */
function fm_get_onlineViewer_exts()
{
    return array('doc', 'docx', 'xls', 'xlsx', 'pdf', 'ppt', 'pptx', 'ai', 'psd', 'dxf', 'xps', 'rar', 'odt', 'ods');
}

/**
 * It returns the mime type of a file based on its extension.
 * @param extension The file extension of the file you want to get the mime type for.
 * @return string|string[] The mime type of the file.
 */
function fm_get_file_mimes($extension)
{
    $fileTypes['swf'] = 'application/x-shockwave-flash';
    $fileTypes['pdf'] = 'application/pdf';
    $fileTypes['exe'] = 'application/octet-stream';
    $fileTypes['zip'] = 'application/zip';
    $fileTypes['doc'] = 'application/msword';
    $fileTypes['xls'] = 'application/vnd.ms-excel';
    $fileTypes['ppt'] = 'application/vnd.ms-powerpoint';
    $fileTypes['gif'] = 'image/gif';
    $fileTypes['png'] = 'image/png';
    $fileTypes['jpeg'] = 'image/jpg';
    $fileTypes['jpg'] = 'image/jpg';
    $fileTypes['webp'] = 'image/webp';
    $fileTypes['avif'] = 'image/avif';
    $fileTypes['rar'] = 'application/rar';

    $fileTypes['ra'] = 'audio/x-pn-realaudio';
    $fileTypes['ram'] = 'audio/x-pn-realaudio';
    $fileTypes['ogg'] = 'audio/x-pn-realaudio';

    $fileTypes['wav'] = 'video/x-msvideo';
    $fileTypes['wmv'] = 'video/x-msvideo';
    $fileTypes['avi'] = 'video/x-msvideo';
    $fileTypes['asf'] = 'video/x-msvideo';
    $fileTypes['divx'] = 'video/x-msvideo';

    $fileTypes['mp3'] = 'audio/mpeg';
    $fileTypes['mp4'] = 'audio/mpeg';
    $fileTypes['mpeg'] = 'video/mpeg';
    $fileTypes['mpg'] = 'video/mpeg';
    $fileTypes['mpe'] = 'video/mpeg';
    $fileTypes['mov'] = 'video/quicktime';
    $fileTypes['swf'] = 'video/quicktime';
    $fileTypes['3gp'] = 'video/quicktime';
    $fileTypes['m4a'] = 'video/quicktime';
    $fileTypes['aac'] = 'video/quicktime';
    $fileTypes['m3u'] = 'video/quicktime';

    $fileTypes['php'] = ['application/x-php'];
    $fileTypes['html'] = ['text/html'];
    $fileTypes['txt'] = ['text/plain'];
    //Unknown mime-types should be 'application/octet-stream'
    if (empty($fileTypes[$extension])) {
        $fileTypes[$extension] = ['application/octet-stream'];
    }
    return $fileTypes[$extension];
}

/**
 * Get info about zip archive
 * @param string $path
 * @return array|bool
 */
function fm_get_zif_info($path, $ext) {
    if ($ext == 'zip' && function_exists('zip_open')) {
        $arch = @zip_open($path);
        if ($arch) {
            $filenames = array();
            while ($zip_entry = @zip_read($arch)) {
                $zip_name = @zip_entry_name($zip_entry);
                $zip_folder = substr($zip_name, -1) == '/';
                $filenames[] = array(
                    'name' => $zip_name,
                    'filesize' => @zip_entry_filesize($zip_entry),
                    'compressed_size' => @zip_entry_compressedsize($zip_entry),
                    'folder' => $zip_folder
                    //'compression_method' => zip_entry_compressionmethod($zip_entry),
                );
            }
            @zip_close($arch);
            return $filenames;
        }
    } elseif($ext == 'tar' && class_exists('PharData')) {
        $archive = new PharData($path);
        $filenames = array();
        foreach(new RecursiveIteratorIterator($archive) as $file) {
            $parent_info = $file->getPathInfo();
            $zip_name = str_replace("phar://".$path, '', $file->getPathName());
            $zip_name = substr($zip_name, ($pos = strpos($zip_name, '/')) !== false ? $pos + 1 : 0);
            $zip_folder = $parent_info->getFileName();
            $zip_info = new SplFileInfo($file);
            $filenames[] = array(
                'name' => $zip_name,
                'filesize' => $zip_info->getSize(),
                'compressed_size' => $file->getCompressedSize(),
                'folder' => $zip_folder
            );
        }
        return $filenames;
    }
    return false;
}

/**
 * Encode html entities
 * @param string $text
 * @return string
 */
function fm_enc($text)
{
    return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
}

/**
 * Prevent XSS attacks
 * @param string $text
 * @return string
 */
function fm_isvalid_filename($text)
{
    return (strpbrk($text, '/?%*:|"<>') === false) ? true : false;
}

/**
 * Language Translation System
 * @param string $txt
 * @return string
 */
function lng($txt)
{
    global $lang;
    $tr['en']['AppName'] = 'Tiny File Manager'; 

    $i18n = fm_get_translations($tr);
    $tr = $i18n;

    if (!strlen($lang)) {
        $lang = 'en';
    }

    if (isset($tr[$lang][$txt])) {
        return fm_enc($tr[$lang][$txt]);
    } else if (isset($tr['en'][$txt])) {
        return fm_enc($tr['en'][$txt]);
    } else {
        return "$txt";
    }
}
?>