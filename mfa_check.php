<?php
/**
 * JSON polling endpoint for mfa_verify.php's background ntfy check.
 * Never called directly by a user — only by the verify page's own JS.
 */

define('AUTH_DIR', __DIR__);
define('AUTH_SESSION_NAME', 'phpauth');

ini_set('session.cookie_httponly', '1');
ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_samesite', 'Lax');
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    ini_set('session.cookie_secure', '1');
}

session_name(AUTH_SESSION_NAME);
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once AUTH_DIR . '/mfa_session.php';
require_once AUTH_DIR . '/mfa_store.php';
require_once AUTH_DIR . '/mfa_ntfy.php';

header('Content-Type: application/json');

function mfa_check_respond(array $data): void {
    echo json_encode($data);
    exit;
}

if (!mfa_pending_active()) {
    mfa_check_respond(['status' => 'no_session']);
}

if (mfa_pending_expired()) {
    mfa_clear_pending_session();
    mfa_check_respond(['status' => 'reset']);
}

if (empty($_SESSION['mfa_ntfy_challenge'])) {
    mfa_check_respond(['status' => 'waiting', 'ntfy_active' => false]);
}

$username = $_SESSION['mfa_pending_user'];
if (auth_lockout_active($username)) {
    mfa_clear_pending_session();
    mfa_check_respond(['status' => 'reset']);
}
$user = mfa_merged_user($username);
if ($user === null || empty($user['ntfy_url'])) {
    mfa_check_respond(['status' => 'waiting', 'ntfy_active' => false]);
}

$challenge = $_SESSION['mfa_ntfy_challenge'];
$since = (int)$_SESSION['mfa_ntfy_since'];

// 5s backdate cushion for clock skew between this server and ntfy's own timestamps.
if (ntfy_check_challenge($user['ntfy_url'], $challenge, $since - 5)) {
    $redirect = safe_redirect($_SESSION['mfa_pending_redirect'] ?? '/');
    $remember = ($_GET['remember'] ?? '0') === '1' && (int)$user['trust_device_days'] > 0;
    mfa_clear_pending_session();
    auth_clear_failures($username);
    session_regenerate_id(true);
    $_SESSION['auth_user'] = $username;
    $_SESSION['auth_time'] = time();
    if ($remember) {
        mfa_set_trust_cookie($username, (int)$user['trust_device_days']);
    }
    mfa_check_respond(['status' => 'approved', 'redirect' => $redirect]);
}

$elapsed = time() - $since;
if ($elapsed > AUTH_MFA_NTFY_CHALLENGE_TTL) {
    // Counted exactly once, however many polls land after expiry.
    if (empty($_SESSION['mfa_ntfy_expired_counted'])) {
        $_SESSION['mfa_ntfy_expired_counted'] = true;
        $accountLocked = auth_record_failure($username);
        if (mfa_register_strike() || $accountLocked) {
            mfa_clear_pending_session();
            mfa_check_respond(['status' => 'reset']);
        }
    }
    mfa_check_respond(['status' => 'waiting', 'ntfy_active' => false]);
}

mfa_check_respond(['status' => 'waiting', 'ntfy_active' => true]);
