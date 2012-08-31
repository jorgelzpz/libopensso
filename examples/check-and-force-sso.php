<?php

require_once('../vendor/autoload.php');

$a = new US\OpenSSO\Handler();

if ($a->check_and_force_sso()) {
	echo "Authenticated";
}
