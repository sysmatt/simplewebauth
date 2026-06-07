<?php
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

        $users = require AUTH_DIR . '/auth_users.php';

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
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: system-ui, sans-serif;
    background: #f0f2f5;
    display: flex;
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
  h1 { font-size: 1.4rem; margin-bottom: 1.5rem; color: #111; }
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
</style>
</head>
<body>
<div class="card">
  <h1>Sign in</h1>
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
</body>
</html>
