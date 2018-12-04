<?php

require_once("x4fcgi.php");

require_once("WxServant.php");

// You are not supposed to echo or print to the output directly.
// Direct outputs will be discarded by x4fcgi_serve().

$servant = new wx\WxServant();

x4fcgi_serve(array($servant, 'process'));

