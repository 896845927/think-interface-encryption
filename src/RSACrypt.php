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
     * a 数组
     * d 整数
     * f 浮点数
     * b 布尔值
     * s 字串
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
use think\Response;

/**
 * 如何设置明文请求调试
 * 1.请求必须是json字串
 * 2.在rsa_config_path文件中将debug设置为true
 * 3.在请求参数param下必须设置'hamburger_coke'=>0,来指定返回数据为明文
 */

class RSACrypt
{
    //将配置文件自动放置在 tp 额外配置目录下
    const rsa_config_path = APP_PATH.'extra'.DIRECTORY_SEPARATOR.'rsa_config.php';

    //tp 自动加载额外配置的目录
    const extra_path = APP_PATH.'extra';

    const exception_response = [
        'miss_config'=>['code'=>100,'message'=>'RSA config missing'],//缺少配置文件
        'request_parse_fail'=>['code'=>101,'message'=>'Request param parsing exception'],//请求参数解析失败
        'request_method_error'=>['code'=>102,'message'=>'Request method error'],//请求方式错误
        'request_param_num_error'=>['code'=>103,'message'=>'Number of request parameters and rules inconsistent'],//请求参数数量与规则不符
        'request_param_error'=>['code'=>104,'message'=>'Error params:'],//错误的请求参数
    ];

    //默认设置返回密文
    protected $response_crypt = 1;

    //生成rsa加密使用的key和配置文件
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
            abort(Response\Json::create(self::exception_response['miss_config']));
    }


    /**
     * 使用魔术方法统一请求和返回入口,作为前置钩子hook
     * @param $name
     * @param $arguments
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
     * 未开启调试模式时,只运行 post 请求
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
     * @param $data
     * @throws \Exception
     */
    protected function throwException($data){
        if (config('rsa_config.debug')){
            throw new \Exception($data['message']);
        }
        abort($this->response($data));
//        abort(Response\Json::create($data));
    }

    /**
     * 请求参数规则检验
     * @param array $param 解析后去除了hamburger_coke标识的请求参数
     * @param array $rule 严格设定的参数规则,['参数名'=>'参数类型']
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
                    case 'a':
                        $param[$k] = (array) $param[$k];
                        break;
                    // 数字
                    case 'd':
                        $param[$k] = (int) $param[$k];
                        break;
                    // 浮点
                    case 'f':
                        $param[$k] = (float) $param[$k];
                        break;
                    // 布尔
                    case 'b':
                        $param[$k] = (boolean) $param[$k];
                        break;
                    // 字符串
                    case 's':
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

    //获取请求参数,必须使用param字段
    protected function request($rule=''){
        $param = request()->param('param');

        //请求开关开启,可以接受明文请求,尝试json解析
        if (config('rsa_config.debug')){
            $request_param = json_decode($param,true);
        }
        //求布尔值,未开启开关,强制密文;是否通过 json 解析出了$request_param
        $bool = config('rsa_config.debug') && isset($request_param) && (boolean)$request_param;

        //解析(开启调试,并 json 解析出数组,则使用明文请求参数;否则,尝试解析密文)
        $request_param = $bool ? $request_param : self::request_decrypt($param,config('rsa_config.request_privKey'));
        //验证请求参数
        if ($request_param === null)
            $this->throwException(self::exception_response['request_parse_fail']);


        //更新返回是否使用密文
        $this->response_crypt = isset($request_param['hamburger_coke']) ? $request_param['hamburger_coke']:0;

        if (isset($request_param['hamburger_coke']))
            unset($request_param['hamburger_coke']);
        //如果严格设定了请求参数规则,则进行检验
        if ($rule)
            $this->paramRuleCheck($request_param,$rule);

        return $request_param;
    }

    //处理返回数字,根据加密请求的参数hamburger_coke来确定返回 密文或明文
    protected function response($response_arr){
        $bool = (boolean)$this->response_crypt==0;
        $response_data = $bool ? $response_arr: self::response_encrypt($response_arr,config('rsa_config.response_pubKey'));
        return Response\Json::create($response_data);
    }

    //请求私钥解密
    protected function request_decrypt($param,$request_privKey){
        $decrypted = $this->ssl_decrypt(base64_decode($param),'private',$request_privKey);
        return json_decode($decrypted,true);
    }
    //返回公钥加密
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