<?php
// 请求的URL信息
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$uri = trim($uri, '/');
// 定义路由规则
$routes = [
    '' => ['name'=>'index','url'=>'index.php'],
    'api' => ['name'=>'api','url'=>'data/api.php'],
    'ci' => ['name'=>'ci','url'=>'data/ci.php'],
];

// 检查是否有匹配的路由
if (isset($routes[$uri])) {
    $functionName = $routes[$uri]['name'];
    $functionUrl = $routes[$uri]['url'];
    
    include($functionUrl);
    die;
    
}elseif($uri=='index.php' || $uri=='index2.php'){
    
}else {
    //检测目录是否存在 --文件夹多层目录
    echo $uri;die;
    if(is_dir($uri)){
        
    }else{
        http_response_code(404);
        echo "Error 404: Page not found";
        die;
    }
}
// 路由对应的函数

?>