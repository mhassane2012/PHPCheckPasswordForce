<?php
/***************************************************************************************
			Example Using Class CheckPasswordForce
***************************************************************************************/

 require_once 'CheckPasswordForce.php';


$checkPasswordForce = new CheckPasswordForce();

$pwd = "1Php@Class";

echo $checkPasswordForce->checkStrongPassword($pwd);