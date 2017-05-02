# think-interface-encryption
Encrypt the JSON-type interface request and return data by using the RSA 

### 预定义了异常 code
 * 100 缺少配置文件
 * 101 请求参数解析失败
 * 102 请求方式错误
 * 103 请求参数数量与规则不符
 * 104 错误的请求参数



### 请求参数支持严格规则
 * $rule 严格设定的参数规则,['参数名'=>'参数类型']
 * 参数类型包括,会强制转换类型
 * array 数组
 * int 整数
 * float 浮点数
 * boolean 布尔值
 * string 字串



### 注意
 * 请求强制要求为json类型,请求数据统一强制使用$_REQUEST['param']来获取(既app端统一请求param来放置请求数据)
 * 配置文件rsa_config.php位于 application/extra目录下
 * debug设置,本地开发环境中设为 true; 线上环境中设为 false;



### 命令行生成配置文件
 * 在项目目录下使用命令行命令 php think MakeRSAConfig



### 对接app
 * 需要提供给APP端rsa_config配置文件里的 request_pubKey 和 response_privKey


### 如何设置明文请求调试
 * 1.请求必须是json字串
 * 2.在rsa_config_path文件中将debug设置为true




生成配置文件命令
php think MakeRSAConfig

调用示例
````
<?php
namespace app\index\controller;

//引用RSACrypt加密类
use mrmiao\encryption\RSACrypt;

class Index
{
    //在方法中实例化加密类
    function encrypt(RSACrypt $crypt){
        //调用request()方法获取请求参数,request方法可选参数数组['参数名'=>'强制转换类型']
        $param = $crypt->request(['user_id'=>'int','mobile'=>'array','quest_time'=>'int','app_id'=>'string']);
        //解析后参数变为明文数据
        $param['php_add'] = '正常使用参数数据';
        //调用response()方法返回数据,参数为数组
        return $crypt->response(['code'=>200,'message'=>'success','data'=>$param]);
    }
}
```
