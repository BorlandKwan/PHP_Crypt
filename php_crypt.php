<?php
/* 
테스트 버전 
PHP_Crypt Version 0.9
PHP 7.3.6
PHP에 mcrypt 모듈은 버전 PHP 7부터 보안성의 문재로 더 이상 지원하지 않는다.
보안을 위해 openssl을 사용해야한다.
hash_hmac을 사용해 문자열을 암호화하고 위변조를 방지하는 방법


주의사항
1. 비밀번호는 반드시 서버만 알고 있어야 한다. 
2. 비밀번호는 절대 클라이언트에게 전송해서는 안된다.
2. 비밀번호는 쉽게 설정하지 않도록 한다.
*/

// error_reporting(E_ALL);
// ini_set("display_errors", 1);

class PHP_Crypt
{
    //기본 설정 부여
    const DEFAULT_HASH = 'sha256'; //사용할 기본 hash 값을 넣어준다. hash_algos() 에서 확인
    const DEFAULT_METHOD =  'aes-256-cbc'; //사용할 기본 openssl method 값을 넣어준다. openssl_get_cipher_methods() 에서 확인
    const DEFAULT_PASSWORD = '|비밀번호||PASSWORD||秘密番號||パスワード|'; //기본 비밀번호 설정
    
    //시작 전  DEFAUL 초기값 확인 후 사용 하시기 바랍니다.
    public function __construct() 
    {
        if( $this->openssl_methods_check(self::DEFAULT_METHOD) === false ) { exit('"DEFAULT_METHOD" Value Error : "'.self::DEFAULT_METHOD.'" is not found or not supported'); }
        if( $this->hash_algo_check(self::DEFAULT_HASH) === false ) { exit('"DEFAULT_HASH" Value Error : "'.self::DEFAULT_HASH.'" is not found or not supported'); }
        if( self::DEFAULT_PASSWORD == null ) { exit('"DEFAULT_PASSWORD" Value Error'); }
    }

    //사용 가능한 openssl method 체크
    private function openssl_methods_check($method)
    {
        if ( empty($method) ) { return (Bool) false; }
        if ( function_exists('openssl_encrypt') and function_exists('openssl_decrypt') ){
            return (Bool) in_array($method, @openssl_get_cipher_methods());
        } else {
            return (Bool) false;
        }
    }

    //사용 가능한 hash algo 체크
    private function hash_algo_check($hash_algo)
    {
        if ( empty($hash_algo) ) { return (Bool) false; }
        if ( function_exists('hash') ) {
            return (Bool) in_array($hash_algo, @hash_algos());
        } else {
            return (Bool) false;
        }
    }

    //자료값 압축
    public function data_compress($data) 
    {
        if ( empty($data) ) { return (Bool) false; }
        if ( function_exists('json_encode') and function_exists('gzdeflate') ) {
            $result = @gzdeflate(json_encode($data), 9);
            return base64_encode($result);
        } else {
            return (Bool) false;
        }
    }

    //자료값 압축해제
    public function data_uncompress($compress_data)
    {
        if ( empty($compress_data) ) { return (Bool) false; }
        if ( function_exists('json_decode') and function_exists('gzinflate') ) {
            $compress_data = base64_decode($compress_data);
            $result = json_decode(@gzinflate($compress_data), true);
            return ($result);
        
        } else {json_decode($data, true);
            return (Bool) false;
        }
    }

    //암호화
    public function encrypt( $plain_text, $password = self::DEFAULT_PASSWORD, $method = self::DEFAULT_METHOD, $hash = self::DEFAULT_HASH )
    {
        //입력된 값이 사용 가능한 openssl method 체크
        $methods_check = $this->openssl_methods_check($method);
        if( $methods_check === false ) { return false; }
        unset($methods_check);

        //입력된 값이 사용 가능한 hash algo 체크
        $hash_check = $this->hash_algo_check($hash);
        if( $hash_check === false ) { return false; }
        unset($hash_check);

        //값 체크
        if ( empty($plain_text) ) { return false;  }
        if ( empty($password) ) { return false;  }

        //용량 절감을 위해 입력값을 압축한다.
        $plain_text = $this->data_compress($plain_text);
        if ( !$plain_text ) { return false; }

        $password = hash($hash, $password, true);

        $iv_size = openssl_cipher_iv_length($method);
        $iv = openssl_random_pseudo_bytes($iv_size);

        //openssl_encrypt 암호화
        $cipher_text = @openssl_encrypt($plain_text, $method, $password, OPENSSL_RAW_DATA, $iv, $tag);
        if ( !$cipher_text ) { return false; }
        unset($plain_text);

        //위변조 방지를 위해 HMAC 코드 생성
        $hash_hmac = hash_hmac($hash, $cipher_text, $password, true);

        //복호화를 위한 값을 포함하여 return
        return base64_encode($iv.'$::'.$hash_hmac.'$::'.$cipher_text.'$::'.$tag);
    }

    //복호화
    public function decrypt( $cipher_text, $password = self::DEFAULT_PASSWORD, $method = self::DEFAULT_METHOD, $hash = self::DEFAULT_HASH )
    {
        //입력된 값이 사용 가능한 openssl method 체크
        $methods_check = $this->openssl_methods_check($method);
        if( $methods_check === false ) { return false; }
        unset($methods_check);

        //입력된 값이 사용 가능한 hash algo 체크
        $hash_check = $this->hash_algo_check($hash);
        if( $hash_check === false ) { return false; }
        unset($hash_check);

        //값 체크
        if ( empty($cipher_text) ) { return false;  }
        if ( empty($password) ) { return false;  }

        $cipher_text = @base64_decode($cipher_text);
        if ( !$cipher_text ) return false;

        $cipher_explode = explode('$::',$cipher_text);
        if ( is_array($cipher_explode) == false or count($cipher_explode) !== 4 ) return false;
        $iv = $cipher_explode[0];
        $hash_hmac = $cipher_explode[1];
        $cipher_data = $cipher_explode[2];
        $tag = $cipher_explode[3];
        unset($cipher_explode);

        $password = hash($hash, $password, true);

        //HMAC를 사용하여 위변조 여부를 체크한다.
        $hmac_check = hash_hmac($hash, $cipher_data, $password, true);
        if ( $hash_hmac !== $hmac_check ) return false;

        //openssl_decrypt 복호화
        $plain_text = @openssl_decrypt($cipher_data, $method, $password, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $iv, $tag);
        if ($plain_text === false) return false;
        unset($cipher_data);

        //압축을 해제하여 입력된 값을 얻는다.
        $plain_text = $this->data_uncompress($plain_text);
        if ($plain_text === false) return false;

        return $plain_text;
    }
}

