<?php

namespace wx;
require_once("xic.php");
require_once("x4fcgi.php");
require_once("wxmsgcrypt.php");

$wxkeyfile = "/xio/private/wxmsgkeys.json";

function xml2array($xml)
{
	$arr = array();
        foreach ($xml->children() as $k => $v)
        {
                $arr[$k] = strval($v);
        }
	return $arr;
}

function array2xml($arr)
{
	$xw = xmlwriter_open_memory();
	xmlwriter_start_element($xw, 'xml');
	foreach ($arr as $k => $v)
	{
		xmlwriter_start_element($xw, $k);
		xmlwriter_text($xw, $v);
		xmlwriter_end_element($xw);
	}
	xmlwriter_end_element($xw);
	return xmlwriter_output_memory($xw);
}

class WxServant extends \xic_Servant
{
	protected function _xic_msg($quest)
	{
		global $wxkeyfile;
		$keys = json_decode(file_get_contents($wxkeyfile), TRUE);

		$appId = $keys["appId"];
		$token = $keys["token"];
		$cryptKey = $keys["cryptKey"];
		$cryptor = new \WxMsgCrypt($appId, $token, $cryptKey);

		$args = $quest->args;

		$auth = $args['auth'];
		$timestamp = $auth['timestamp'];
		$nonce = $auth['nonce'];
		$signature = $auth['signature'];

		$lcache = \xic_createProxy("LCache");
		$tnkey = $timestamp . '+' . $nonce . '+' . $signature;
		$answer = $lcache->invoke("get_and_set", array('key'=>$tnkey, 'value'=>1, 'expire'=>60));
		if ($answer['value'] != NULL)
		{
			throw new Exception("Replay Attack?");
		}

		$arr = array($token, $timestamp, $nonce);
		sort($arr, SORT_STRING);
		$hash = sha1(implode('', $arr));

		if ($hash != $signature)
		{
			throw new Exception("Auth failed");
		}

		$msg = $args['msg'];
		$encrypt_type = $auth['encrypt_type'];
		if ($encrypt_type == 'aes')
		{
			$cryptor->decryptIncoming($timestamp, $nonce, $msg['Encrypt'], $auth['msg_signature'], $plain);
			$xml = simplexml_load_string($plain);
			$msg = xml2array($xml);
		}
		dlog("", "RECV", json_encode($msg));

		$msgType = $msg["MsgType"];

		$text = "OK";
		if ($msgType == 'event')
		{
			$event = $msg['Event'];
			$eventKey = $msg['EventKey'];
			if ($event == 'subscribe')
			{
				$text = "Welcome";
			}
			else if ($event == 'unsubscribe')
			{
				$text = "Bye bye";
			}
		}
		else
		{
			$msgId = $msg["MsgId"];
			if ($msgType == 'text')
			{
				$content = $msg["Content"];
				$text = $content;
			}
			else if ($msgType == 'image')
			{
				$picUrl = $msg["PicUrl"];
				$mediaId = $msg["MediaId"];
			}
			else if ($msgType == 'file')
			{
				$title = $msg["Title"];
				$description = $msg["Description"];
				$fileKey = $msg["FileKey"];
				$fileMd5 = $msg["FileMd5"];
				$fileLen = $msg["FileTotalLen"];
			}
		}

		$reply = array(
			"FromUserName"=>$msg["ToUserName"],
			"ToUserName"=>$msg["FromUserName"],
			"MsgType"=>"text",
			"Content"=>$text,
			"CreateTime"=>time(),
		);
		dlog("", "SEND", json_encode($reply));

		if ($encrypt_type == 'aes')
		{
			$plain = array2xml($reply);
			$o_timestamp = time();
			$o_nonce = mt_rand();
			$cryptor->encryptOutgoing($o_timestamp, $o_nonce, $plain, $o_cipher, $o_sig);
			$reply = array("TimeStamp"=>$o_timestamp,
				"Nonce"=>$o_nonce,
				"Encrypt"=>$o_cipher,
				"MsgSignature"=>$o_sig,
				);
		}
		
		return array("msg"=>$reply);
	}
}

