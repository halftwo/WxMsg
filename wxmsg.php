<?php

require_once("xic.php");

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
		if (substr_compare($k, '__x4fcgi_', 0, 9) == 0)
		{
			continue;
		}
		xmlwriter_start_element($xw, $k);
		xmlwriter_text($xw, $v);
		xmlwriter_end_element($xw);
	}
	xmlwriter_end_element($xw);
	return xmlwriter_output_memory($xw);
}

function main()
{
	$timestamp = @$_GET['timestamp'];
	$nonce = @$_GET['nonce'];
	$signature = @$_GET['signature'];

	if ($signature == '' || $nonce == '' || $timestamp == '')
	{
		dlog(xic_self_id(), "AUTH", "NO_PARAMS");
		print "invalid request\n";
		exit();
	}

	$diff = intval($timestamp) - time();
	if ($diff < -30 || $diff > 30)
	{
		dlog(xic_self_id(), "AUTH", "INVALID_TIMESTAMP");
		print "invalid timestamp\n";
		exit();
	}

	$lcache = xic_createProxy("LCache");
	$tnkey = $timestamp . '+' . $nonce . '+' . $signature;
	$answer = $lcache->invoke("get_and_set", array('key'=>$tnkey, 'value'=>1, 'expire'=>60));
	if ($answer['value'] != NULL)
	{
		dlog(xic_self_id(), "AUTH", "REPLAY_ATTACK");
		print "replay attack?\n";
		exit();
	}

	$echostr = @$_GET['echostr'];
	if ($echostr != "")
	{
		dlog(xic_self_id(), "CONF", "SETUP");
		print $echostr;
		exit();
	}


	// Handle the msg
	$input_fp = fopen("php://input", "rb");
	$input_bytes = stream_get_contents($input_fp);
	fclose($input_fp);

	dlog(xic_self_id(), "MSG", $input_bytes);
	$xml = simplexml_load_string($input_bytes);
	if ($xml === FALSE)
	{
		print "invalid xml\n";
		exit();
	}

	$msg = xml2array($xml);
	$prx = xic_createProxy("WxMsg");
	$answer = $prx->invoke("msg", array("auth"=>$_GET, "msg"=>$msg));

	$output_bytes = array2xml($answer['msg']);
	dlog(xic_self_id(), "OUT", $output_bytes);
	print $output_bytes;
}


try
{
	main();
}
catch (Throwable $ex)
{
	dlog(xic_self_id(), "EXCEPTION", $ex);
	print "exception occurs\n";
}

