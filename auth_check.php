<?php
/**
 * auth_check.php - nginx auth_request endpoint for simplewebauth
 *
 * Returns 200 if the session is valid, 401 if not.
 * Never redirects. Never call this directly in a browser (nginx blocks it
 * via the 'internal' directive).
 *
 * SECURITY: nothing may be output before the status code is set. With
 * output_buffering off, any byte sent early (whitespace before <?php, a BOM,
 * a PHP warning) flushes the headers with the default 200 status, and every
 * request would pass auth_request. Buffer everything, and refuse to answer
 * 200 unless we still control the status line.
 */

ob_start();

if (!defined('AUTH_USERS_FILE')) {
    // Prefer the .ini format (required for MFA) if it's been deployed;
    // otherwise fall back to the legacy scalar-string .php format untouched.
    define('AUTH_USERS_FILE', is_file('/etc/simplewebauth/auth_users.ini')
        ? '/etc/simplewebauth/auth_users.ini'
        : '/etc/simplewebauth/auth_users.php');
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
if (session_status() === PHP_SESSION_NONE && !session_start()) {
    http_response_code(401);
    exit;
}

if (
    !headers_sent() &&
    isset($_SESSION['auth_user'], $_SESSION['auth_time']) &&
    (time() - $_SESSION['auth_time']) < AUTH_SESSION_LIFETIME
) {
    $_SESSION['auth_time'] = time();   // slide the session expiry
    http_response_code(200);
    header('X-Auth-User: ' . $_SESSION['auth_user']);  // optional, passes username downstream
    ob_end_clean();
    exit;
}

http_response_code(401);
ob_end_clean();
exit;
