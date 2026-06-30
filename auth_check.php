 <?php
/**
 * auth_check.php - nginx auth_request endpoint for simplewebauth
 *
 * Returns 200 if the session is valid, 401 if not.
 * Never redirects. Never call this directly in a browser (nginx blocks it
 * via the 'internal' directive).
 */

if (!defined('AUTH_USERS_FILE')) {
    define('AUTH_USERS_FILE', '/etc/simplewebauth/auth_users.php');
}

define('AUTH_SESSION_LIFETIME', 28800);   // must match auth.php (8 hours)
define('AUTH_SESSION_NAME',     'phpauth'); // must match auth.php

ini_set('session.cookie_httponly', '1');
ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_samesite', 'Lax');

// Keep PHP's session GC from reaping the session file before our own
// AUTH_SESSION_LIFETIME check expires it (must match auth.php).
ini_set('session.gc_maxlifetime', (string)AUTH_SESSION_LIFETIME);

if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    ini_set('session.cookie_secure', '1');
}

session_name(AUTH_SESSION_NAME);
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (
    isset($_SESSION['auth_user'], $_SESSION['auth_time']) &&
    (time() - $_SESSION['auth_time']) < AUTH_SESSION_LIFETIME
) {
    $_SESSION['auth_time'] = time();   // slide the session expiry
    http_response_code(200);
    header('X-Auth-User: ' . $_SESSION['auth_user']);  // optional, passes username downstream
    exit;
}

http_response_code(401);
exit; 
