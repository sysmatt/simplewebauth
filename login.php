<?php
define('AUTH_DIR', __DIR__);
define('AUTH_SESSION_NAME', 'phpauth');

if (!defined('AUTH_USERS_FILE')) {
    define('AUTH_USERS_FILE', '/etc/simplewebauth/auth_users.php');
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

$error = '';
$redirect = $_GET['redirect'] ?? $_POST['redirect'] ?? '';

// Validate redirect stays on the same host
function safe_redirect(string $url): string {
    if (empty($url)) return '/';
    $host = parse_url($url, PHP_URL_HOST);
    if ($host && $host !== $_SERVER['HTTP_HOST']) return '/';
    return $url;
}
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

        $users = require AUTH_USERS_FILE;

        if (
            $username !== '' &&
            isset($users[$username]) &&
            password_verify($password, $users[$username])
        ) {
            session_regenerate_id(true);
            $_SESSION['auth_user'] = $username;
            $_SESSION['auth_time'] = time();
            unset($_SESSION['csrf_token']);
            header('Location: ' . $redirect);
            exit;
        } else {
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

// Load optional UI customization from ../simplewebauth-config.php (docroot, outside code tree)
$ui = [];
$uiConfigFile = dirname(AUTH_DIR) . '/simplewebauth-config.php';
if (is_file($uiConfigFile)) {
    $ui = (array)(require $uiConfigFile);
}
$uiAppName    = htmlspecialchars($ui['app_name']    ?? 'Sign in', ENT_QUOTES);
$uiLogoUrl    = htmlspecialchars($ui['logo_url']    ?? '',         ENT_QUOTES);
$uiLogoAlt    = htmlspecialchars($ui['logo_alt']    ?? '',         ENT_QUOTES);
$uiBanner     = $ui['banner'] ?? '';   // rendered as HTML — admin-controlled
$uiFooter     = $ui['footer'] ?? '';   // rendered as HTML — admin-controlled
$uiBgImageUrl = htmlspecialchars($ui['bg_image_url'] ?? '', ENT_QUOTES);
// Default scrim when a background image is set; set to '' to disable the overlay entirely
$uiBgOverlay  = htmlspecialchars(
    array_key_exists('bg_overlay', $ui) ? (string)$ui['bg_overlay'] : 'rgba(0,0,0,0.45)',
    ENT_QUOTES
);
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
