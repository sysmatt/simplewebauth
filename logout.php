<?php
define('AUTH_SESSION_NAME', 'phpauth');
define('AUTH_DIR', __DIR__);

session_name(AUTH_SESSION_NAME);
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$_SESSION = [];
session_destroy();

// Derive login URL the same way auth.php does — avoids hardcoding /login.php
// when simplewebauth is deployed as a subdirectory (e.g. /simplewebauth/login.php)
$loginAbs    = realpath(AUTH_DIR . '/login.php');
$loginRelUrl = str_replace(rtrim($_SERVER['DOCUMENT_ROOT'], '/'), '', $loginAbs);
header('Location: ' . $loginRelUrl);
exit;
