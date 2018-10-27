<?php


class WxMsgCrypt
{
	private $cryptMode = "AES-256-CBC";
	private $appId;
	private $token;
	private $cryptKey;

	public function __construct($appId, $token, $cryptKey)
	{
		$this->appId = $appId;
		$this->token = $token;
		$this->cryptKey = base64_decode($cryptKey.'=');
	}

	public function decryptIncoming($timestamp, $nonce, $cipher, $signature, &$plain)
	{
		$mysig = $this->_computeSignature($timestamp, $nonce, $cipher);
		if ($mysig != $signature) {
			throw new Exception("invalid signature");
		}

		$plain = $this->_decrypt($cipher);
	}

	public function encryptOutgoing($timestamp, $nonce, $plain, &$cipher, &$signature)
	{
		$cipher = $this->_encrypt($plain);
		$signature = $this->_computeSignature($timestamp, $nonce, $cipher);
	}

	private function _computeSignature($timestamp, $nonce, $cipher)
	{
		$arr = array($this->token, $timestamp, $nonce, $cipher);
		sort($arr, SORT_STRING);
		$str = implode($arr);
		return sha1($str);
	}

	private function _decrypt($cipher)
	{
		// $cipher is base64 encoded
		$iv = substr($this->cryptKey, 0, 16);
		$text = openssl_decrypt($cipher, $this->cryptMode, $this->cryptKey, OPENSSL_ZERO_PADDING, $iv);
		if ($text === FALSE) {
			throw new Exception("openssl_decrypt failed");
		}

		$padsize = ord(substr($text, -1));
		if ($padsize < 1 || $padsize > 32) {
			throw new Exception("invalid padding size $padsize");
		}
		$pad = str_repeat(chr($padsize), $padsize);
		if ($pad != substr($text, -$padsize)) {
			throw new Exception("invalid padding bytes");
		}

		$text = substr($text, 0, strlen($text) - $padsize);
		$plainSize = unpack("N", substr($text, 16, 4))[1];

		$appId = substr($text, 20 + $plainSize);
		if ($appId != $this->appId) {
			throw new Exception("appId not match");
		}

		$plain = substr($text, 20, $plainSize);
		return $plain;
	}

	private function _encrypt($plain)
	{
		$random = openssl_random_pseudo_bytes(16);
		$text = $random . pack("N", strlen($plain)) . $plain . $this->appId;

		$padsize = 32 - strlen($text) % 32;
		$pad = str_repeat(chr($padsize), $padsize);
		$text = $text . $pad;

		$iv = substr($this->cryptKey, 0, 16);
		$cipher = openssl_encrypt($text, $this->cryptMode, $this->cryptKey, OPENSSL_ZERO_PADDING, $iv);
		return $cipher;	// base64 encoded
	}
}


