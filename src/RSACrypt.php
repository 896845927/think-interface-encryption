<?php
namespace mrmiao\encryption;

/**
 * 预定义了异常 code
 * 100 缺少配置文件
 * 101 请求参数解析失败
 * 102 请求方式错误
 * 103 请求参数数量与规则不符
 * 104 错误的请求参数
 */

/**
 * 请求参数支持严格规则
 * $rule 严格设定的参数规则,['参数名'=>'参数类型']
 * 参数类型包括,会强制转换类型
 * array 数组
 * int 整数
 * float 浮点数
 * boolean 布尔值
 * string 字串
 */

/**
 * 注意
 * 配置文件rsa_config.php位于 application/extra目录下
 * debug设置,本地开发环境中设为 true; 线上环境中设为 false;
 */

/**
 * 命令行生成配置文件
 * 在项目目录下使用命令行命令 php think MakeRSAConfig
 */

/**
 * 对接app
 * 需要提供给APP端rsa_config配置文件里的 request_pubKey 和 response_privKey
 */

/**
 * 如何设置明文请求调试
 * 1.在rsa_config_path文件中将debug设置为true
 */

class RSACrypt
{
    //将配置文件自动放置在 tp 额外配置目录下
    const rsa_config_path = APP_PATH.'extra'.DIRECTORY_SEPARATOR.'rsa_config.php';

    //tp 自动加载额外配置的目录
    const extra_path = APP_PATH.'extra';

    //预设的异常数组
    const exception_response = [
        'miss_config'=>['code'=>100,'message'=>'RSA config missing'],//缺少配置文件
        'request_parse_fail'=>['code'=>101,'message'=>'Request param parsing exception'],//请求参数解析失败
        'request_method_error'=>['code'=>102,'message'=>'Request method error'],//请求方式错误
        'request_param_num_error'=>['code'=>103,'message'=>'Number of request parameters and rules inconsistent'],//请求参数数量与规则不符
        'request_param_error'=>['code'=>104,'message'=>'Error params:'],//错误的请求参数
    ];


    //生成配置文件的方法,为php命令行调用,生成rsa加密使用的key和配置文件
    static function makeRSAKey(){
        //如果不存在自动加载的额外配置目录,则创建
        if (!file_exists(self::extra_path))
            mkdir(self::extra_path);
        //检查到不存在 rsa 配置文件,则创建
        $path_name = self::rsa_config_path;
        if (!file_exists($path_name)){
            $config = array('private_key_bits' => 1024);
            $res = openssl_pkey_new($config);
            openssl_pkey_export($res, $request_privKey);
            $request_pubKey = openssl_pkey_get_details($res);
            $request_pubKey = $request_pubKey["key"];

            $res = openssl_pkey_new($config);
            openssl_pkey_export($res, $response_privKey);
            $response_pubKey = openssl_pkey_get_details($res);
            $response_pubKey = $response_pubKey["key"];


            $content = <<<EOT
<?php
//配置文件
return [
    'debug'=>true,
    'request_privKey'=>'{$request_privKey}',
    'request_pubKey'=>'{$request_pubKey}',
    'response_privKey'=>'{$response_privKey}',
    'response_pubKey'=>'{$response_pubKey}',
];
EOT;

            file_put_contents($path_name,$content);
        }
    }

    //类初始化时检查是否存在配置文件
    public function __construct(){
        if (!file_exists(self::rsa_config_path))
            abort(json(self::exception_response['miss_config']));
    }


    /**
     * 使用魔术方法统一请求和返回入口,作为前置钩子hook
     * @param $name,请求方法名
     * @param $arguments,请求参数数组
     * @return mixed
     * @throws \Exception
     */
    public function __call($name, $arguments){
        //请求时,优先检查请求方法(当前未支持 RESTful 路由模式,因此请求统一为 post)
        if ($name == "request")
            self::checkRequestMethod();

        return call_user_func_array([__CLASS__,$name],$arguments);
    }

    /**
     * 请求方式检查
     * 调试模式,不限制请求类型
     * 接口模式,限制为只接受post请求
     */
    protected function checkRequestMethod(){
        if (config('rsa_config.debug')==false){
            if (!(request()->method() == 'POST')){
                $this->throwException(self::exception_response['request_method_error']);
            }
        }
    }

    /**
     * 抛出异常
     * 调试模式,抛出html格式异常
     * 接口模式,向app端发送json提示
     * @param $data
     * @throws \Exception
     */
    protected function throwException($data){
        if (config('rsa_config.debug')){
            throw new \Exception($data['message']);
        }
        abort(json($data));
    }

    /**
     * 请求参数规则检验
     * @param array $param 数组,经过解析的明文数组格式请求参数
     * @param array $rule 严格设定的参数规则,['参数名'=>'参数类型']
     * 各参数根据规则强制转换变量类型
     * 抛出异常情况:
     * 1.请求参数数量与规则不符
     * 2.请求参数名称与规则不符
     */
    protected function paramRuleCheck(&$param,$rule){
        $pc = count($param);
        $rc = count($rule);
        //检查参数数量
        if ($pc!=$rc){
            $this->throwException(self::exception_response['request_param_num_error']);
        }

        //检查参数名称和值
        foreach ($rule as $k=>$v){
            if (empty($param[$k])){
                $error_param[] = $k;
            }else{
                switch (strtolower($v)) {
                    // 数组
                    case 'array':
                        $param[$k] = (array) $param[$k];
                        break;
                    // 数字
                    case 'int':
                        $param[$k] = (int) $param[$k];
                        break;
                    // 浮点
                    case 'float':
                        $param[$k] = (float) $param[$k];
                        break;
                    // 布尔
                    case 'boolean':
                        $param[$k] = (boolean) $param[$k];
                        break;
                    // 字符串
                    case 'string':
                    default:
                        if (is_scalar($param[$k])) {
                            $param[$k] = (string) $param[$k];
                        } else {
                            $error_param[] = $k;
                        }
                }
            }
        }

        if (!empty($error_param)){
            $error = self::exception_response['request_param_error'];
            $error['message'] = $error['message'].implode(',',$error_param);
            $this->throwException($error);
        }

    }

    /**
     * 加密类获取请求参数的统一方法
     * 接口模式下,密文请求统一放在参数param下
     * @param string $rule,数组,可选参数,设定请求参数检测规则
     * @return mixed
     */
    protected function request($rule=''){

        //请求开关开启,可以接受明文请求,尝试json解析
        if (config('rsa_config.debug')){
            $request_param = request()->param();
        }else{
            $param = request()->param('param');
            $request_param = self::request_decrypt($param,$this->rsa_config['rsa_config.request_privKey']);
        }

        //验证请求参数
        if ($request_param === null)
            $this->throwException(self::exception_response['request_parse_fail']);

        //如果严格设定了请求参数规则,则进行检验
        if ($rule)
            $this->paramRuleCheck($request_param,$rule);

        return $request_param;
    }

    /**
     * 处理返回数据
     * @param $response_arr,数组,加密类要返回的数据
     * @param bool $encrypt,布尔值,决定是否对返回数据加密,默认不加密
     * @return mixed
     */
    protected function response($response_arr,$encrypt=false){
        $response_data = $encrypt ?
            self::response_encrypt($response_arr,config('rsa_config.response_pubKey')):
            $response_arr;
        return json($response_data);
    }

    /**
     * 使用$request_privKey为请求密文解密
     * 先对请求密文进行base64解码,再进行密文解密
     * @param $param,请求密文
     * @param $request_privKey,私钥,RSA算法,为请求密文数据解密用,app端存有对应公钥
     * @return mixed
     */
    protected function request_decrypt($param,$request_privKey){
        $decrypted = $this->ssl_decrypt(base64_decode($param),'private',$request_privKey);
        return json_decode($decrypted,true);
    }

    /**
     * 使用$response_pubKey为返回数据加密
     * 为了密文乱码支持传输,对加密后密文进行base64转换
     * @param $response_arr,数组,返回数据明文,要加密的数据
     * @param $response_pubKey,公钥,RSA算法,为返回数据加密用,app端存有对应私钥
     * @return string
     */
    protected function response_encrypt($response_arr,$response_pubKey){
        //公钥加密
        $encrypted = $this->ssl_encrypt(json_encode($response_arr),'public',$response_pubKey);
        return base64_encode($encrypted);
    }

    //分段加密方法
    protected function ssl_encrypt($source,$type,$key){
        //Assumes 1024 bit key and encrypts in chunks.

        $maxlength=117;
        $output='';
        while($source){
            $input= substr($source,0,$maxlength);
            $source=substr($source,$maxlength);
            if($type=='private'){
                $ok= openssl_private_encrypt($input,$encrypted,$key);
            }else{
                $ok= openssl_public_encrypt($input,$encrypted,$key);
            }

            $output.=$encrypted;
        }
        return $output;
    }

    //分段解密方法
    protected function ssl_decrypt($source,$type,$key){
        // The raw PHP decryption functions appear to work
        // on 128 Byte chunks. So this decrypts long text
        // encrypted with ssl_encrypt().

        $maxlength=128;
        $output='';
        while($source){
            $input= substr($source,0,$maxlength);
            $source=substr($source,$maxlength);
            if($type=='private'){
                $ok= openssl_private_decrypt($input,$out,$key);
            }else{
                $ok= openssl_public_decrypt($input,$out,$key);
            }

            $output.=$out;
        }
        return $output;

    }
}