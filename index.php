<?php
/* 테스트 페이지 입니다. */
include_once( $_SERVER['DOCUMENT_ROOT'].'/php_crypt.php' );

$test = new PHP_Crypt;

$input = '안녕하세요'; //입력된 값
$a = $test->encrypt($input); //암호화
$b = $test->decrypt($a) ; //복호화

echo '입력된 값 : '.$input.'<br />';
echo '암호화 : '.$a.' <br />';
echo '복호화 : '.$b.' <br />';
?>