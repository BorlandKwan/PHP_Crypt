<?php

/* 
테스트 버전 
PHP 7.3.6
*/

//error_reporting(E_ALL);
//ini_set("display_errors", 1);

class PHP_Crypt{

    const KEY = 'Passwoard(눈_눈)@1234'; /*  <---- need password !!!!   */

    public function  __construct(){
        if( empty(self::KEY) or is_null(self::KEY) ){ exit(' const KEY 값이 필요합니다.'); }
    }

    public function encrypt($plaintext, $password = self::KEY) {

        if( empty($plaintext) or is_null($plaintext) ) { return false; }
        if( empty($password) or is_null($password) ) { return false; }

        $plaintext = gzcompress($plaintext);
        $password = hash('sha256', $password, true);

        $method = 'AES-256-CBC';
        $ivlen = openssl_cipher_iv_length($method);
        $iv = openssl_random_pseudo_bytes($ivlen);

        $ciphertext = openssl_encrypt($plaintext, $method, $password, OPENSSL_RAW_DATA, $iv);
        $hash = hash_hmac('sha256', $ciphertext, $password, true);

        return base64_encode($iv.$hash.$ciphertext);
    }
    
    public function decrypt($ciphertext, $password = self::KEY) {

        if( empty($ciphertext) or is_null($ciphertext) ) { return false; }
        if( empty($password) or is_null($password) ) { return false; }

        $ciphertext = @base64_decode($ciphertext, true); 
        $password = hash('sha256', $password, true);

        if($ciphertext == false){ return false; } 

        $method = 'AES-256-CBC';
        $ivlen = openssl_cipher_iv_length($method);
        $iv = substr($ciphertext, 0, $ivlen);
        $hash = substr($ciphertext, $ivlen, 32);
        $ciphertext_row = substr($ciphertext, 48);

        $hash_check = hash_hmac('sha256', $ciphertext_row, $password, true);
        if ($hash !== $hash_check) return false;

        $plaintext = openssl_decrypt($ciphertext_row, $method, $password, OPENSSL_RAW_DATA, $iv);
        if ($plaintext === false) return false;

        $plaintext = @gzuncompress($plaintext);
        if ($plaintext === false) return false;
       
        return $plaintext;
    }

}

?>