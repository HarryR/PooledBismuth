<?php
function database () {
    $file_db = new PDO('sqlite:../.pool.db');
    $file_db->setAttribute(PDO::ATTR_ERRMODE,  PDO::ERRMODE_EXCEPTION);
    $file_db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    return $file_db;
}

function param($name, $default=NULL) {
	if( isset($_GET[$name]) )
		return $_GET[$name];
	return $default;
}

$db = database();
