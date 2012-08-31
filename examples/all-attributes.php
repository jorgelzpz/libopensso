<?php

require_once('../vendor/autoload.php');

$a = new US\OpenSSO\Handler();

if ($a->check_and_force_sso()) {
	echo '<h1>Your attributes:</h1>';
	$attr = $a->all_attributes(TRUE);
	foreach ($attr as $name => $values) {
		echo '<h2>' . $name . '</h2>';
		echo '<ul>';
		foreach ($values as $v) {
			echo '<li>' . $v . '</li>';
		}
		echo '</ul>';
	}
}

