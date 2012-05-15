<?php

require_once('../vendor/autoload.php');

$a = new OpenSSO\Handler();

if ($a->check_sso()) {
	$a->logout();
} else {
	echo 'You are not logged in';
}
