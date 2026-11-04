<?php
define('AUTH_DIR', __DIR__);
define('AUTH_SESSION_NAME', 'phpauth');

if (!defined('AUTH_USERS_FILE')) {
    // Prefer the .ini format (required for MFA) if it's been deployed;
    // otherwise fall back to the legacy scalar-string .php format untouched.
    define('AUTH_USERS_FILE', is_file('/etc/simplewebauth/auth_users.ini')
        ? '/etc/simplewebauth/auth_users.ini'
        : '/etc/simplewebauth/auth_users.php');
}

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

// Fixed, canned message only — never render an arbitrary query-string value.
$error = ($_GET['notice'] ?? '') === 'mfa_reset'
    ? 'Too many incorrect attempts. Please sign in again.'
    : '';
$redirect = $_GET['redirect'] ?? $_POST['redirect'] ?? '';

// Validate redirect stays on this site (allowlist — see safe_redirect())
require_once AUTH_DIR . '/mfa_session.php';
$redirect = safe_redirect($redirect);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF check
    if (
        empty($_POST['csrf_token']) ||
        !hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'])
    ) {
        $error = 'Invalid request. Please try again.';
    } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        require_once AUTH_DIR . '/mfa_store.php';
        $user = $username !== '' ? mfa_merged_user($username) : null;

        // Per-account lockout (see AUTH_LOCKOUT_* in mfa_config.php). The
        // password is still checked while locked so timing doesn't change,
        // and a locked account gets the same generic error as a wrong
        // password, so the lockout itself isn't an oracle.
        $locked = $user !== null && auth_lockout_active($username);
        $passwordOk = $user !== null && password_verify($password, $user['password_hash']);

        if ($passwordOk && !$locked) {
            session_regenerate_id(true);

            // Trusted-device bypass — re-checked against the user's CURRENT
            // trust_device_days setting every time, not just at issuance, so
            // setting it to 0 immediately stops honoring any tokens already
            // handed out, not just future ones.
            $trustBypass = false;
            if (!empty($user['mfa_enabled']) && (int)$user['trust_device_days'] > 0) {
                $trustToken = $_COOKIE[AUTH_MFA_TRUST_COOKIE_NAME] ?? '';
                $trustBypass = $trustToken !== '' && mfa_check_trust_token($username, $trustToken);
            }

            if (!empty($user['mfa_enabled']) && !$trustBypass) {
                // Password verified — second factor still required. Nothing
                // is finalized (auth_user/auth_time) until mfa_verify.php
                // confirms a TOTP code, a backup code, or an ntfy reply.
                $_SESSION['mfa_pending_user']     = $username;
                $_SESSION['mfa_pending_since']    = time();
                $_SESSION['mfa_pending_redirect'] = $redirect;
                $_SESSION['mfa_pending_strikes']  = 0;
                unset($_SESSION['csrf_token']);

                if (!empty($user['ntfy_url'])) {
                    require_once AUTH_DIR . '/mfa_ntfy.php';
                    $challenge = ntfy_generate_challenge();
                    $_SESSION['mfa_ntfy_challenge']       = $challenge;
                    $_SESSION['mfa_ntfy_since']           = time();
                    $_SESSION['mfa_ntfy_expired_counted'] = false;
                    // The challenge is NEVER included in the push itself — only
                    // the browser session that's actually signing in ever sees
                    // it (rendered on mfa_verify.php). Anyone who can merely
                    // read this ntfy topic must still see the live login screen
                    // to know what to reply with; embedding the code in the
                    // push would let topic read-access alone approve sign-ins.
                    // Fired once, immediately — arrives alongside the code
                    // dialog rather than on request. An unsolicited push is
                    // itself a signal the password may be compromised.
                    ntfy_publish(
                        $user['ntfy_url'],
                        'SimpleWebAuth sign-in',
                        "Someone is signing in to your account. If this is you, enter the code shown " .
                        "on your screen into this app. If you didn't just try to sign in, your password " .
                        "may be compromised — change it now."
                    );
                }

                $verifyAbs = realpath(AUTH_DIR . '/mfa_verify.php');
                $docRoot = rtrim($_SERVER['DOCUMENT_ROOT'], '/');
                header('Location: ' . str_replace($docRoot, '', $verifyAbs));
                exit;
            }

            // Complete sign-in (no MFA, or a trusted device) — only now does
            // the failure count reset. With MFA it resets in mfa_verify.php/
            // mfa_check.php once the second factor passes, never here: a
            // correct password alone must not buy fresh MFA guesses.
            auth_clear_failures($username);
            $_SESSION['auth_user'] = $username;
            $_SESSION['auth_time'] = time();
            unset($_SESSION['csrf_token']);
            header('Location: ' . $redirect);
            exit;
        } else {
            if ($user !== null && !$passwordOk && !$locked) {
                auth_record_failure($username);
            }
            // Constant-time delay to slow brute force
            usleep(300000);
            $error = 'Invalid username or password.';
        }
    }
}

// Generate CSRF token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['csrf_token'];
$redirectHtml = htmlspecialchars($redirect, ENT_QUOTES);
$errorHtml = $error ? '<p class="error">' . htmlspecialchars($error, ENT_QUOTES) . '</p>' : '';

// Shared with mfa_verify.php/mfa_enroll.php so the whole flow, not just this
// screen, carries the same visual identity.
require_once AUTH_DIR . '/branding.php';
$b = auth_branding();
$uiAppName    = $b['app_name'];
$uiLogoUrl    = $b['logo_url'];
$uiLogoAlt    = $b['logo_alt'];
$uiBanner     = $b['banner'];
$uiFooter     = $b['footer'];
$uiBgImageUrl = $b['bg_image_url'];
$uiBgOverlay  = $b['bg_overlay'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= $uiAppName ?></title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: system-ui, sans-serif;
    background: #f0f2f5;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
  }
  .card {
    background: #fff;
    border-radius: 8px;
    box-shadow: 0 2px 12px rgba(0,0,0,.12);
    padding: 2.5rem 2rem;
    width: 100%;
    max-width: 360px;
  }
  .logo { display: block; max-width: 160px; max-height: 80px; margin: 0 auto 1.25rem; }
  h1 { font-size: 1.4rem; margin-bottom: .5rem; color: #111; }
  .banner { font-size: .85rem; color: #666; margin-bottom: 1.25rem; }
  label { display: block; font-size: .85rem; color: #555; margin-bottom: .25rem; }
  input[type=text], input[type=password] {
    width: 100%; padding: .6rem .75rem;
    border: 1px solid #ccc; border-radius: 5px;
    font-size: 1rem; margin-bottom: 1rem;
    outline: none; transition: border-color .2s;
  }
  input:focus { border-color: #4f8ef7; }
  button {
    width: 100%; padding: .7rem;
    background: #4f8ef7; color: #fff;
    border: none; border-radius: 5px;
    font-size: 1rem; cursor: pointer;
    transition: background .2s;
  }
  button:hover { background: #3a7ae0; }
  .error { color: #c0392b; font-size: .9rem; margin-bottom: 1rem; }
  .footer { margin-top: 1.25rem; font-size: .8rem; color: #999; text-align: center; }
  .footer a { color: #999; }
</style>
<?php if ($uiBgImageUrl): ?>
<style>
  body {
    background-image: url('<?= $uiBgImageUrl ?>');
    background-size: cover;
    background-position: center;
    background-repeat: no-repeat;
    background-attachment: fixed;
  }
  <?php if ($uiBgOverlay): ?>
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background: <?= $uiBgOverlay ?>;
    z-index: 0;
  }
  .card, .footer { position: relative; z-index: 1; }
  <?php endif; ?>
</style>
<?php endif; ?>
</head>
<body>
<div class="card">
  <?php if ($uiLogoUrl): ?>
  <img class="logo" src="<?= $uiLogoUrl ?>" alt="<?= $uiLogoAlt ?>">
  <?php endif; ?>
  <h1><?= $uiAppName ?></h1>
  <?php if ($uiBanner): ?>
  <div class="banner"><?= $uiBanner ?></div>
  <?php endif; ?>
  <?= $errorHtml ?>
  <form method="post" autocomplete="on">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES) ?>">
    <input type="hidden" name="redirect" value="<?= $redirectHtml ?>">
    <label for="username">Username</label>
    <input type="text" id="username" name="username" required autofocus autocomplete="username">
    <label for="password">Password</label>
    <input type="password" id="password" name="password" required autocomplete="current-password">
    <button type="submit">Sign in</button>
  </form>
</div>
<?php if ($uiFooter): ?>
<div class="footer"><?= $uiFooter ?></div>
<?php endif; ?>
</body>
</html>
