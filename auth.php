<?php
/**
 * Drop-in auth guard. Add this to the top of any PHP utility:
 *   require __DIR__ . '/simplewebauth/auth.php';
 *
 * Adjust AUTH_DIR if simplewebauth/ lives elsewhere relative to your utilities.
 */

define('AUTH_DIR', __DIR__);
define('AUTH_SESSION_LIFETIME', 28800); // 8 hours in seconds
define('AUTH_SESSION_NAME', 'phpauth');
define('AUTH_LOGIN_PAGE', AUTH_DIR . '/login.php');

// Path to the users file — override by defining this constant before requiring auth.php
if (!defined('AUTH_USERS_FILE')) {
    define('AUTH_USERS_FILE', '/etc/simplewebauth/auth_users.php');
}

// Harden session cookies
ini_set('session.cookie_httponly', '1');
ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_samesite', 'Lax');

// Keep PHP's session GC from reaping the session file before our own
// AUTH_SESSION_LIFETIME check expires it — otherwise sessions can be
// garbage-collected after the server's default gc_maxlifetime (often
// ~24 min) regardless of the 8-hour timeout implied above.
ini_set('session.gc_maxlifetime', (string)AUTH_SESSION_LIFETIME);

// Use HTTPS-only cookies if the request is over HTTPS
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    ini_set('session.cookie_secure', '1');
}

session_name(AUTH_SESSION_NAME);
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Check session validity
$authenticated = false;
if (
    isset($_SESSION['auth_user'], $_SESSION['auth_time']) &&
    (time() - $_SESSION['auth_time']) < AUTH_SESSION_LIFETIME
) {
    $authenticated = true;
    // Slide the expiry on activity
    $_SESSION['auth_time'] = time();
}

if (!$authenticated) {
    $redirect = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http')
        . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    $loginUrl = str_replace(AUTH_DIR, '', AUTH_LOGIN_PAGE);
    // Build a relative URL to login.php from the document root
    $docRoot = rtrim($_SERVER['DOCUMENT_ROOT'], '/');
    $loginRelPath = str_replace($docRoot, '', realpath(AUTH_LOGIN_PAGE));
    header('Location: ' . $loginRelPath . '?redirect=' . urlencode($redirect));
    exit;
}

/**
 * Returns the currently logged-in username.
 */
function auth_user(): string {
    return $_SESSION['auth_user'] ?? '';
}
