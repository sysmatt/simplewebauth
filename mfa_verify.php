<?php
/**
 * Second-factor verification — reached after login.php verifies the password
 * but before a session is finalized. Accepts a TOTP code OR a backup code in
 * a single field (dispatched by length), while polling in the background for
 * an ntfy push reply if the user has one enrolled. Any method matching wins.
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
require_once AUTH_DIR . '/mfa_totp.php';

if (!mfa_pending_active()) {
    header('Location: ' . mfa_relative_url('login.php'));
    exit;
}

if (mfa_pending_expired()) {
    mfa_clear_pending_session();
    header('Location: ' . mfa_relative_url('login.php') . '?notice=mfa_reset');
    exit;
}

$username = $_SESSION['mfa_pending_user'];
$user = mfa_merged_user($username);
if ($user === null || empty($user['mfa_enabled'])) {
    // Defensive — shouldn't happen, but never leave a dangling pending state.
    mfa_clear_pending_session();
    header('Location: ' . mfa_relative_url('login.php'));
    exit;
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['mfa_csrf_token'] ?? '', $_POST['csrf_token'])) {
        $error = 'Invalid request. Please try again.';
    } else {
        $code = trim($_POST['code'] ?? '');
        $matched = false;

        if (preg_match('/^\d{6}$/', $code) && !empty($user['totp_secret'])) {
            $matched = totp_verify($user['totp_secret'], $code);
        } elseif (strlen($code) === AUTH_MFA_BACKUP_CODE_LENGTH && !empty($user['backup_codes'])) {
            $matched = mfa_verify_backup_code($username, $user['backup_codes'], $code);
        }

        if ($matched) {
            $redirect = safe_redirect($_SESSION['mfa_pending_redirect'] ?? '/');
            $remember = !empty($_POST['remember_device']) && (int)$user['trust_device_days'] > 0;
            mfa_clear_pending_session();
            session_regenerate_id(true);
            $_SESSION['auth_user'] = $username;
            $_SESSION['auth_time'] = time();
            if ($remember) {
                mfa_set_trust_cookie($username, (int)$user['trust_device_days']);
            }
            header('Location: ' . $redirect);
            exit;
        }

        // Constant-time delay to slow brute force, same convention as login.php.
        usleep(300000);

        if (mfa_register_strike()) {
            mfa_clear_pending_session();
            header('Location: ' . mfa_relative_url('login.php') . '?notice=mfa_reset');
            exit;
        }
        $error = 'Incorrect code. Please try again.';
    }
}

if (empty($_SESSION['mfa_csrf_token'])) {
    $_SESSION['mfa_csrf_token'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['mfa_csrf_token'];
$ntfyActive = !empty($_SESSION['mfa_ntfy_challenge']);
$ntfyChallenge = $_SESSION['mfa_ntfy_challenge'] ?? '';
$trustDays = (int)($user['trust_device_days'] ?? AUTH_MFA_TRUST_DEVICE_DAYS);
$attemptsLeft = max(0, AUTH_MFA_MAX_ATTEMPTS - ($_SESSION['mfa_pending_strikes'] ?? 0));
$errorHtml = $error ? '<p class="error">' . htmlspecialchars($error, ENT_QUOTES) . '</p>' : '';
$loginUrlJs = mfa_relative_url('login.php');

// Shared with login.php/mfa_enroll.php so the whole flow carries one visual identity.
require_once AUTH_DIR . '/branding.php';
$b = auth_branding();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Verify — <?= $b['app_name'] ?></title>
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
    max-width: 380px;
  }
  h1 { font-size: 1.3rem; margin-bottom: .5rem; color: #111; }
  .sub { font-size: .85rem; color: #666; margin-bottom: 1.25rem; }
  label { display: block; font-size: .85rem; color: #555; margin-bottom: .25rem; }
  input[type=text] {
    width: 100%; padding: .6rem .75rem;
    border: 1px solid #ccc; border-radius: 5px;
    font-size: 1.15rem; letter-spacing: .15em; text-align: center;
    margin-bottom: 1rem; outline: none; transition: border-color .2s;
  }
  input:focus { border-color: #4f8ef7; }
  button {
    width: 100%; padding: .7rem;
    background: #4f8ef7; color: #fff;
    border: none; border-radius: 5px;
    font-size: 1rem; cursor: pointer; transition: background .2s;
  }
  button:hover { background: #3a7ae0; }
  .error { color: #c0392b; font-size: .9rem; margin-bottom: 1rem; }
  .push-status {
    font-size: .85rem; color: #666; margin-bottom: 1.25rem;
    padding: .6rem .75rem; background: #f7f9fc; border-radius: 5px;
    text-align: center;
  }
  .push-status.expired { background: #fdf2ec; color: #a8672f; }
  .push-code {
    display: block; font-size: 1.8rem; font-weight: 700; letter-spacing: .3em;
    font-family: ui-monospace, monospace; margin: .35rem 0 .15rem;
  }
  .attempts { font-size: .78rem; color: #999; margin-top: .75rem; text-align: center; }
  .remember-label {
    display: flex; align-items: flex-start; gap: .5rem;
    font-size: .8rem; color: #666; margin-bottom: 1rem; cursor: pointer;
  }
  .remember-label input { margin-top: .2rem; }
  .logo { display: block; max-width: 160px; max-height: 80px; margin: 0 auto 1.25rem; }
  .banner { font-size: .85rem; color: #666; margin-bottom: 1.25rem; }
  .footer { margin-top: .25rem; font-size: .8rem; color: #999; text-align: center; }
  .footer a { color: #999; }
</style>
<?php if ($b['bg_image_url']): ?>
<style>
  body {
    background-image: url('<?= $b['bg_image_url'] ?>');
    background-size: cover;
    background-position: center;
    background-repeat: no-repeat;
    background-attachment: fixed;
  }
  <?php if ($b['bg_overlay']): ?>
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background: <?= $b['bg_overlay'] ?>;
    z-index: 0;
  }
  .card, .footer { position: relative; z-index: 1; }
  <?php endif; ?>
</style>
<?php endif; ?>
</head>
<body>
<div class="card">
  <?php if ($b['logo_url']): ?>
  <img class="logo" src="<?= $b['logo_url'] ?>" alt="<?= $b['logo_alt'] ?>">
  <?php endif; ?>
  <h1>Verify it's you</h1>
  <?php if ($b['banner']): ?>
  <div class="banner"><?= $b['banner'] ?></div>
  <?php endif; ?>
  <p class="sub">Enter your authenticator code or a backup code.</p>
  <?= $errorHtml ?>
  <?php if ($ntfyActive): ?>
  <div class="push-status" id="pushStatus">
    A notification was also sent to your phone — enter this code there to approve:
    <span class="push-code"><?= htmlspecialchars($ntfyChallenge, ENT_QUOTES) ?></span>
    <span id="pushWaitingLabel">Waiting for your reply&hellip;</span>
  </div>
  <?php endif; ?>
  <form method="post" autocomplete="off">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES) ?>">
    <label for="code">Code</label>
    <input type="text" id="code" name="code" autofocus autocomplete="one-time-code" maxlength="<?= (int)AUTH_MFA_BACKUP_CODE_LENGTH ?>">
    <?php if ($trustDays > 0): ?>
    <label class="remember-label">
      <input type="checkbox" name="remember_device" id="rememberDevice">
      Remember this device for <?= $trustDays ?> days — don't check this on a shared or public computer
    </label>
    <?php endif; ?>
    <button type="submit">Verify</button>
  </form>
  <p class="attempts"><?= $attemptsLeft ?> attempt<?= $attemptsLeft === 1 ? '' : 's' ?> remaining</p>
</div>
<?php if ($b['footer']): ?>
<div class="footer"><?= $b['footer'] ?></div>
<?php endif; ?>
<?php if ($ntfyActive): ?>
<script>
(function () {
  var statusEl = document.getElementById('pushStatus');
  var loginUrl = <?= json_encode($loginUrlJs) ?>;
  var rememberBox = document.getElementById('rememberDevice');
  function poll() {
    var remember = rememberBox && rememberBox.checked ? '1' : '0';
    fetch('mfa_check.php?remember=' + remember, { credentials: 'same-origin' })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data.status === 'approved') {
          // Server already validates this (safe_redirect); never navigate to
          // anything but a same-site path or an http(s) URL regardless.
          var dest = String(data.redirect || '/');
          window.location = /^(\/(?![\/\\])|https?:\/\/)/i.test(dest) ? dest : '/';
        } else if (data.status === 'reset') {
          window.location = loginUrl + '?notice=mfa_reset';
        } else if (data.status === 'no_session') {
          window.location = loginUrl;
        } else if (data.ntfy_active) {
          setTimeout(poll, 2000);
        } else {
          statusEl.textContent = 'Push expired — use a code instead.';
          statusEl.classList.add('expired');
        }
      })
      .catch(function () { setTimeout(poll, 3000); });
  }
  setTimeout(poll, 1500);
})();
</script>
<?php endif; ?>
</body>
</html>
