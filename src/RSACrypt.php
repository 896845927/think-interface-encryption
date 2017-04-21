<?php
namespace mrmiao\encryption;

/**
 * 注意
 * 配置文件rsa_config.php位于 application/extra目录下
 * 在正式服务器环境中,必须把rsa_config_path文件中的debug设置为false
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
 * 1.请求必须是json字串
 * 2.在rsa_config_path文件中将debug设置为true
 * 3.在请求参数param下必须设置'hamburger_coke'=>0,来指定返回数据为明文
 */

class RSACrypt
{
    const rsa_config_path = APP_PATH.'extra'.DIRECTORY_SEPARATOR.'rsa_config.php';
    const extra_path = APP_PATH.'extra';

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

    /**
     * 使用魔术方法统一请求和返回入口,作为前置钩子hook
     * @param $name
     * @param $arguments
     * @return mixed
     * @throws \Exception
     */
    public function __call($name, $arguments){
        if (!file_exists(self::rsa_config_path))
            throw new \Exception('RSA Config Missing');

        return call_user_func_array([__CLASS__,$name],$arguments);
    }


    //获取请求参数,必须使用param字段
    protected function request(){
        $param = request()->param('param');

        //请求开关开启,可以接受明文请求,尝试json解析
        if (config('rsa_config.debug')){
            $request_param = json_decode($param,true);
        }
        //求布尔值,未开启开关,强制密文;是否通过 json 解析出了$request_param
        $bool = config('rsa_config.debug') && isset($request_param) && (boolean)$request_param;

        //解析
        $request_param = $bool ? $request_param : self::request_decrypt($param,config('rsa_config.request_privKey'));
        if ($request_param === null)
            throw new \Exception('Request Param Abnormal');

        //更新返回是否使用密文
        $this->response_crypt = isset($request_param['hamburger_coke']) ? $request_param['hamburger_coke']:0;

        if (isset($request_param['hamburger_coke']))
            unset($request_param['hamburger_coke']);

        return $request_param;
    }

    //处理返回数字,根据加密请求的参数hamburger_coke来确定返回 密文或明文
    protected function response($response_arr){
        $bool = (boolean)$this->response_crypt==0;
        return $bool ? json_encode($response_arr): self::response_encrypt($response_arr,config('rsa_config.response_pubKey'));
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