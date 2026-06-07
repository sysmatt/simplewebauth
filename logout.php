<?php
define('AUTH_SESSION_NAME', 'phpauth');

session_name(AUTH_SESSION_NAME);
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$_SESSION = [];
session_destroy();

header('Location: /login.php');
exit;
