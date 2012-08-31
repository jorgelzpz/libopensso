<?php

require_once('../vendor/autoload.php');

$a = new US\OpenSSO\Handler();

if ($a->check_sso()) {
	echo "Authenticated";
} else {
	echo "Anonymous";
}
