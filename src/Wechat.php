<?php

namespace musickr\musickr;

use think\exception\HttpException;

class Wechat
{
    private $config;
    private $access_token;

    public function __construct($config)
    {
        $this->config = $config;
    }

    /**
     * 获取用户
     * @param $code
     * @return mixed
     */
    public function getUser($code)
    {
        $param = [
            'appid' => $this->config['app_id'],
            'secret' => $this->config['secret'],
            'js_code' => $code,
            'grant_type' => 'authorization_code'
        ];
        $urlParams = $this->toUrlParams($param);
        $api_path = "https://api.weixin.qq.com/sns/jscode2session" . "?" . $urlParams;
        $res = json_decode($this->curl($api_path));
        if (property_exists($res, 'errcode')) {
            throw new HttpException($res->errcode, $res->errmsg);
        }
        return $res;
    }

    public function userInfo($sessionKey,$encryptedData, $iv)
    {
        return $this->decryptData($this->config['app_id'], $sessionKey, $encryptedData, $iv);
    }


    private function getAccessToken()
    {
        $this->access_token = cache('access_token');

        if (!$this->access_token) {
            $param = [
                'grant_type' => 'client_credential',
                'appid' => $this->config['app_id'],
                'secret' => $this->config['secret']
            ];
            $urlParams = $this->toUrlParams($param);
            $api_path = "https://api.weixin.qq.com/cgi-bin/token" . "?" . $urlParams;
            $res = json_decode($this->curl($api_path));
            if (property_exists($res, 'errcode')) {
                throw new HttpException($res->errcode, $res->errmsg);
            }
            $this->access_token = $res->access_token;
//            echo $res->expires_in;die;
            cache('access_token', $res->access_token, $res->expires_in);
        }
        return $this;
    }

    /**
     * 微信信息解密
     * @param string $appid 小程序id
     * @param string $sessionKey 小程序密钥
     * @param string $encryptedData 在小程序中获取的encryptedData
     * @param string $iv 在小程序中获取的iv
     * @return array 解密后的数组
     */
    function decryptData($appid, $sessionKey, $encryptedData, $iv)
    {
        if (strlen($sessionKey) != 24) {
            throw new HttpException('403','请检查您的登录状态');

        }
        $aesKey = base64_decode($sessionKey);
        if (strlen($iv) != 24) {
            throw new HttpException('403','编码字段iv不合法');
        }
        $aesIV = base64_decode($iv);
        $aesCipher = base64_decode($encryptedData);
        $result = openssl_decrypt($aesCipher, "AES-128-CBC", $aesKey, 1, $aesIV);
        $dataObj = json_decode($result);
        if ($dataObj == NULL) {
            throw new HttpException('404','找不到您的用户信息');
        }
        if ($dataObj->watermark->appid != $appid) {
            throw new HttpException('500','请检查微信配置');
        }
        $data = json_decode($result, true);
        return $result;
    }

    /**
     * 请求过程中因为编码原因+号变成了空格
     * 需要用下面的方法转换回来
     */
    function define_str_replace($data)
    {
        return str_replace(' ', '+', $data);
    }


    //获取手机号
    public function number($appid , $sessionKey, $encryptedData, $iv)
    {
        include_once (ROOT_PATH."./public/author/wxBizDataCrypt.php"); //引入 wxBizDataCrypt.php 文件
        $appid = $appid;
        $sessionKey = $sessionKey;
        $encryptedData= $encryptedData;
        $iv = $iv;
        $data = '';

        $pc = new \WXBizDataCrypt($appid, $sessionKey); //注意使用\进行转义
        $errCode = $pc->decryptData($encryptedData, $iv, $data );
        if ($errCode == 0) {
            print($data . "\n");
        } else {
            print($errCode . "\n");
        }
    }

    /**
     * 生成签名
     * @param $values
     * @return string 本函数不覆盖sign成员变量，如要设置签名需要调用SetSign方法赋值
     */
    private function makeSign($values)
    {
        //签名步骤一：按字典序排序参数
        ksort($values);
        $string = $this->toUrlParams($values);
        //签名步骤二：在string后加入KEY
        $string = $string . '&key=' . $this->config['apiKey'];
        //签名步骤三：MD5加密
        $string = md5($string);
        //签名步骤四：所有字符转为大写
        return strtoupper($string);
    }

    /**
     * 格式化参数格式化成url参数
     * @param $values
     * @return string
     */
    private function toUrlParams($values)
    {
        $buff = '';
        foreach ($values as $k => $v) {
            if ($k != 'sign' && $v != '' && !is_array($v)) {
                $buff .= $k . '=' . $v . '&';
            }
        }
        return trim($buff, '&');
    }

    /**
     * 以post方式提交xml到对应的接口url
     * @param $xml
     * @param $url
     * @param int $second
     * @return mixed
     */
    private function postXmlCurl($xml, $url, $second = 30)
    {
        $ch = curl_init();
        // 设置超时
        curl_setopt($ch, CURLOPT_TIMEOUT, $second);
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);//严格校验
        // 设置header
        curl_setopt($ch, CURLOPT_HEADER, FALSE);
        // 要求结果为字符串且输出到屏幕上
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        // post提交方式
        curl_setopt($ch, CURLOPT_POST, TRUE);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $xml);
        // 运行curl
        $data = curl_exec($ch);
        curl_close($ch);
        return $data;
    }

    /**
     * 输出xml字符
     * @param $values
     * @return bool|string
     */
    private function toXml($values)
    {
        if (!is_array($values)
            || count($values) <= 0
        ) {
            return false;
        }

        $xml = "<xml>";
        foreach ($values as $key => $val) {
            if (is_numeric($val)) {
                $xml .= "<" . $key . ">" . $val . "</" . $key . ">";
            } else {
                $xml .= "<" . $key . "><![CDATA[" . $val . "]]></" . $key . ">";
            }
        }
        $xml .= "</xml>";
        return $xml;
    }

    /**
     * 将xml转为array
     * @param $xml
     * @return mixed
     */
    private function fromXml($xml)
    {
        // 禁止引用外部xml实体
        libxml_disable_entity_loader(true);
        return json_decode(json_encode(simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA)), true);
    }

    /**
     * curl请求指定url
     * @param $url
     * @param array $data
     * @return mixed
     */
    function curl($url, $data = [])
    {
        // 处理get数据
        if (!empty($data)) {
            $url = $url . '?' . http_build_query($data);
        }
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_HEADER, false);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        //curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);//这个是重点。
        $result = curl_exec($curl);
        curl_close($curl);
        return $result;
    }

    /**
     * 支付成功异步通知
     * @param \app\task\model\Order $OrderModel
     * @throws \app\common\exception\BaseException
     * @throws \Exception
     * @throws \think\exception\DbException
     */
    public function notify()
    {
        //        $xml = <<<EOF
        //<xml><appid><![CDATA[wx62f4cad175ad0f90]]></appid>
        //<attach><![CDATA[test]]></attach>
        //<bank_type><![CDATA[ICBC_DEBIT]]></bank_type>
        //<cash_fee><![CDATA[1]]></cash_fee>
        //<fee_type><![CDATA[CNY]]></fee_type>
        //<is_subscribe><![CDATA[N]]></is_subscribe>
        //<mch_id><![CDATA[1499579162]]></mch_id>
        //<nonce_str><![CDATA[963b42d0a71f2d160b3831321808ab79]]></nonce_str>
        //<openid><![CDATA[o9coS0eYE8pigBkvSrLfdv49b8k4]]></openid>
        //<out_trade_no><![CDATA[2018062448524950]]></out_trade_no>
        //<result_code><![CDATA[SUCCESS]]></result_code>
        //<return_code><![CDATA[SUCCESS]]></return_code>
        //<sign><![CDATA[E252025255D59FE900DAFA4562C4EF5C]]></sign>
        //<time_end><![CDATA[20180624122501]]></time_end>
        //<total_fee>1</total_fee>
        //<trade_type><![CDATA[JSAPI]]></trade_type>
        //<transaction_id><![CDATA[4200000146201806242438472701]]></transaction_id>
        //</xml>
        //EOF;
        if (!$xml = file_get_contents('php://input')) {
            $this->returnCode(false, 'Not found DATA');
        }
        $myfile = fopen("newfile.txt", "w") or die("Unable to open file!");

        $txt = $xml . "\n";
        fwrite($myfile, $txt);
        fclose($myfile);
        // 将服务器返回的XML数据转化为数组
        $data = $this->fromXml($xml);
        $rechargeModel = new Recharge();
        $frModel = new FinanceRecord();
        $recharge = $rechargeModel->details($data['out_trade_no']);

        // 订单信息
        empty($recharge) && $this->returnCode(true, '订单不存在');
        // 保存微信服务器返回的签名sign
        $dataSign = $data['sign'];
        // sign不参与签名算法
        unset($data['sign']);
        // 生成签名
        $sign = $this->makeSign($data);
        // 判断签名是否正确  判断支付状态

        if (($sign === $dataSign)
            && ($data['return_code'] == 'SUCCESS')
            && ($data['result_code'] == 'SUCCESS')) {

            $rechargeOrder = $rechargeModel->updateStatus($data['out_trade_no'], 2);
            if ($rechargeOrder->recharge_user_type == 1) {
                $model = new FinanceRecord();
                $model->recharge($recharge);
            } else if ($rechargeOrder->recharge_user_type == 2) {
                company_recharge_callback($rechargeOrder);
            }

            // 返回状态
            $this->returnCode(true);
        }
        // 返回状态
        $this->returnCode(false, '签名失败');
    }

    /**
     * 返回状态给微信服务器
     * @param bool $is_success
     * @param string $msg
     */
    private function returnCode($is_success = true, $msg = null)
    {

        $xml_post = $this->toXml([
            'return_code' => $is_success ? $msg ?: 'SUCCESS' : 'FAIL',
            'return_msg' => $is_success ? 'OK' : $msg,
        ]);
        die($xml_post);
    }
}

