# PHP_Crypt

테스트 PHP 버전은 7.3.6 입니다.
보안문제로 mcrypt 방식은 사용하지 않기로 하였기때문에 OpenSSL 방식으로 대체해 적용해보았습니다.

<?
include_once( $_SERVER['DOCUMENT_ROOT'].'/php_crypt.php' );

$test = new PHP_Crypt;

$input = '안녕하세요'; //입력된 값
$a = $test->encrypt($input); //암호화
$b = $test->decrypt($a) ; //복호화

echo '입력된 값 : '.$input.'<br />'; //출력
echo '암호화 : '.$a.' <br />';  //출력
echo '복호화 : '.$b.' <br />';  //출력
?>
