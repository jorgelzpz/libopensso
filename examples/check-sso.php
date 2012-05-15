<?php

require_once('../vendor/autoload.php');

$a = new OpenSSO\Handler();

if ($a->check_sso()) {
	echo "Authenticated";
} else {
	echo "Anonymous";
}
