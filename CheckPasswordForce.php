<?php
/**
* Class CheckPasswordForce 
* 
* This simple PHP class can check password strength policies.
* The class can check enforce password length rules,the use of upper and lower case letters, numbers and special characters.
*
* @param   string  $pwd  password.
* @return  string  the messages of error or success (Strong or average).
* @access  public
* @version 1.0 / 2021-07-08
* @author  Hassane Moussa <mhassane2012@gmail.com>
* @ Niger / Niamey
*/
class CheckPasswordForce  
{
    private 

	$_length =8,			// Define the lenght at least of the password
	$pcentLengthPwd,		// Percentage of the lenght password criteria variable
	$pcentUppLetter =10,	// Percentage of at least an uppercase letter
	$pcentLowLetter =10, 	// Percentage of at least an lowercase letter
	$pcentNum =10,			// Percentage of at least an number
	$pcentSymbol =10,		// Percentage of at least an special symbol
	$msg_error_length,
	$msg_error_miss_number,
	$msg_error_miss_lower_letter,
	$msg_error_miss_upper_letter,
	$msg_error_miss_special_character,
	$out_msg,
	$msg_success;
	

	/**
   * Return the error message of password length
   * @param void
   * @return string
   */
	public function getErrorLength(){
		$this->msg_error_length = "Password must be at least $this->_length characters in length!";
		return $this->msg_error_length;
    }
	/**
   * Return the error message of miss number in password
   * @param void
   * @return string
   */
	public function getErrorMissNumber(){
		$this->msg_error_miss_number = "Password must contain at least one number!";
		return $this->msg_error_miss_number;
    }
	/**
   * Return the error message of miss least one lower case letter in password
   * @param void
   * @return string
   */
	public function getErrorMissLowerLetter(){
		$this->msg_error_miss_lower_letter = "Password must contain at least one lower case letter!";
		return $this->msg_error_miss_lower_letter;
    }
	/**
   * Return the error message of miss least one upper case letter in password
   * @param void
   * @return string
   */	
	public function getErrorMissUpperLetter(){
		$this->msg_error_miss_upper_letter = "Password must contain at least one upper case letter!";
		return $this->msg_error_miss_upper_letter;
    }
	/**
   * Return the error message of miss least one special character in password
   * @param void
   * @return string
   */	
	public function getErrorMissSpecialCharacter(){
		$this->msg_error_miss_special_character = "Password must contain at least one special character!";
		return $this->msg_error_miss_special_character;
    }
	/**
   * Return the success message of strong or average password
   * @param pwd
   * @return string
   */	
	public function getMsgSuccess($pwd){
		if ($this->getMergePcentPwdCriteria($pwd) == 80){ $this->msg_success = "Your password is average!"; }
		elseif ($this->getMergePcentPwdCriteria($pwd) > 80){ $this->msg_success = "Your password is strong!"; }
		else{ $this->msg_success = "Your password is Weak !"; }
		return $this->msg_success;
    }
	/**
   * Return the length of password
   * @param password
   * @return int
   */	
	public function getPasswordLength($pwd){
		return strlen($pwd);
    }
	/**
   * Return the percentage of the password length criteria :
   * [0, 8[ words : 0% || 8 words : 40% || ]8, +∞[ words : 60%
   * @param password
   * @return int
   */	
	public function getPcentPasswordLengthCriteria($pwd){
		
		if($this->getPasswordLength($pwd) == $this->_length){
			$this->pcentLengthPwd = 40;
		}elseif($this->getPasswordLength($pwd) > $this->_length){
			$this->pcentLengthPwd = 60;
		}else{
			$this->pcentLengthPwd = 0;
		}
		
		return $this->pcentLengthPwd;
    }
	/**
   * Return the percentage of the password length criteria :
   * Password contain at least Lower Letter
   * @param password
   * @return int
   */	
	public function getPcentPwdAtLeastLowerLetter($pwd){
		
		if(preg_match("([a-z]+)",$pwd)){
			$this->out_msg = $this->pcentLowLetter;
		}else{
			$this->out_msg = 0;
		}
		
		return $this->out_msg;
    }
	/**
   * Return the percentage of the password length criteria :
   * Password contain at least Upper Letter
   * @param password
   * @return int
   */	
	public function getPcentPwdAtLeastUpperLetter($pwd){
		
		if(preg_match("([A-Z]+)",$pwd)){
			$this->out_msg = $this->pcentUppLetter;
		}else{
			$this->out_msg = 0;
		}
		
		return $this->out_msg;
    }
	/**
   * Return the percentage of the password length criteria :
   * Password contain at least an number
   * @param password
   * @return int
   */	
	public function getPcentPwdAtLeastNumber($pwd){
		
		if(preg_match("([0-9]+)",$pwd)){
			$this->out_msg = $this->pcentNum;
		}else{
			$this->out_msg = 0;
		}
		
		return $this->out_msg;
    }
	/**
   * Return the percentage of the password length criteria :
   * Password contain at least an special symbol
   * @param password
   * @return int
   */	
	public function getPcentPwdAtLeastSymbol($pwd){
		
		if(preg_match("([-_?.*@!$&#%^~{}]+)",$pwd)){
			$this->out_msg = $this->pcentSymbol;
		}else{
			$this->out_msg = 0;
		}
		
		return $this->out_msg;
    }
	/**
   * Return the percentage of the password length criteria :
   * Merge all percentages
   * @param password
   * @return int
   */	
	public function getMergePcentPwdCriteria($pwd){
		
		$this->out_msg = $this->getPcentPasswordLengthCriteria($pwd) + $this->getPcentPwdAtLeastLowerLetter($pwd) + $this->getPcentPwdAtLeastUpperLetter($pwd) + $this->getPcentPwdAtLeastNumber($pwd) + $this->getPcentPwdAtLeastSymbol($pwd);
		
		return $this->out_msg;
    }
	/**
   * Return the messages of error or success (Strong or average) 
   * @param password
   * @return String
   */	
	public function checkStrongPassword($pwd){
		
		if($this->getPcentPasswordLengthCriteria($pwd)==0){ $this->out_msg = $this->getErrorLength(); }
		elseif($this->getPcentPwdAtLeastLowerLetter($pwd)==0){ $this->out_msg = $this->getErrorMissLowerLetter(); }
		elseif($this->getPcentPwdAtLeastUpperLetter($pwd)==0){ $this->out_msg = $this->getErrorMissUpperLetter(); }
		elseif($this->getPcentPwdAtLeastNumber($pwd)==0){ $this->out_msg = $this->getErrorMissNumber(); }
		elseif($this->getPcentPwdAtLeastSymbol($pwd)==0){ $this->out_msg = $this->getErrorMissSpecialCharacter(); }
		else{
			
			$this->out_msg = $this->getMsgSuccess($pwd);
		}
		
		return $this->out_msg;
	
    }		
	
	
	
	
}

?>