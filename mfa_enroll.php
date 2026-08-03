<?php
/**
 * Self-service MFA enrollment — only reachable when AUTH_ALLOW_SELF_MFA is
 * enabled. Requires an already-authenticated session (auth.php). Writes only
 * to the local overlay file; never touches the main vault-managed file.
 */

require __DIR__ . '/auth.php';

if (!AUTH_ALLOW_SELF_MFA) {
    http_response_code(403);
    exit('Self-service MFA enrollment is disabled on this install.');
}

require_once AUTH_DIR . '/mfa_store.php';
require_once AUTH_DIR . '/mfa_totp.php';
require_once AUTH_DIR . '/mfa_ntfy.php';
require_once AUTH_DIR . '/mfa_qr.php';

$username = auth_user();
$user = mfa_merged_user($username);
$action = $_POST['action'] ?? '';
$message = '';
$messageIsError = false;
$revealedCodes = [];

function enroll_generate_backup_codes_if_needed(string $username, array $user): array {
    if (!empty($user['backup_codes'])) {
        return [];
    }
    $plain = mfa_generate_backup_codes();
    mfa_write_local_fields($username, ['backup_codes' => mfa_hash_backup_codes($plain)]);
    return $plain;
}

if (empty($_SESSION['enroll_csrf_token'])) {
    $_SESSION['enroll_csrf_token'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['enroll_csrf_token'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (empty($_POST['csrf_token']) || !hash_equals($csrf, $_POST['csrf_token'])) {
        $message = 'Invalid request. Please try again.';
        $messageIsError = true;
    } elseif ($action === 'start_totp') {
        $_SESSION['enroll_totp_secret'] = totp_generate_secret();
    } elseif ($action === 'cancel_totp') {
        unset($_SESSION['enroll_totp_secret']);
    } elseif ($action === 'verify_totp') {
        $secret = $_SESSION['enroll_totp_secret'] ?? '';
        $code = trim($_POST['code'] ?? '');
        if ($secret !== '' && totp_verify($secret, $code)) {
            $revealedCodes = enroll_generate_backup_codes_if_needed($username, $user);
            mfa_write_local_fields($username, ['mfa_enabled' => true, 'totp_secret' => $secret]);
            unset($_SESSION['enroll_totp_secret']);
            $message = 'Authenticator app confirmed and enrolled.';
            $user = mfa_merged_user($username);
        } else {
            usleep(300000);
            $message = "That code didn't match — try again.";
            $messageIsError = true;
        }
    } elseif ($action === 'start_ntfy') {
        $topic = ntfy_generate_topic_url(AUTH_NTFY_SERVER);
        $challenge = ntfy_generate_challenge();
        ntfy_publish($topic, 'SimpleWebAuth enrollment', "Reply with {$challenge} to confirm this device.");
        $_SESSION['enroll_ntfy_url']       = $topic;
        $_SESSION['enroll_ntfy_challenge'] = $challenge;
        $_SESSION['enroll_ntfy_since']     = time();
    } elseif ($action === 'cancel_ntfy') {
        unset($_SESSION['enroll_ntfy_url'], $_SESSION['enroll_ntfy_challenge'], $_SESSION['enroll_ntfy_since']);
    }
}

// mfa_enroll_check.php (ntfy confirmation poll) stashes freshly generated
// backup codes here since it runs on a separate request from the JS reload —
// shown exactly once, then discarded.
if (!empty($_SESSION['enroll_reveal_codes'])) {
    $revealedCodes = $_SESSION['enroll_reveal_codes'];
    unset($_SESSION['enroll_reveal_codes']);
}

$totpEnrolled = !empty($user['totp_secret']);
$ntfyEnrolled = !empty($user['ntfy_url']);
$hasBackupCodes = !empty($user['backup_codes']);
$totpPending = !empty($_SESSION['enroll_totp_secret']);
$ntfyPending = !empty($_SESSION['enroll_ntfy_url']);

$totpQr = null;
$totpUri = '';
if ($totpPending) {
    $totpUri = totp_provisioning_uri($_SESSION['enroll_totp_secret'], $username, 'SimpleWebAuth');
    $totpQr = qr_svg($totpUri);
}
$ntfyQr = null;
if ($ntfyPending) {
    $ntfyQr = qr_svg($_SESSION['enroll_ntfy_url']);
}

// Shared with login.php/mfa_verify.php so the whole flow carries one visual identity.
require_once AUTH_DIR . '/branding.php';
$b = auth_branding();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Two-Factor Setup — <?= $b['app_name'] ?></title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #f0f2f5; padding: 2rem 1rem; }
  .wrap { max-width: 480px; margin: 0 auto; }
  .page-logo { display: block; max-width: 160px; max-height: 80px; margin: 0 auto 1rem; }
  .page-banner { font-size: .85rem; color: #666; margin-bottom: 1.25rem; text-align: center; }
  .footer { margin-top: .25rem; font-size: .8rem; color: #999; text-align: center; }
  .footer a { color: #999; }
  .card {
    background: #fff; border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,.12);
    padding: 1.75rem; margin-bottom: 1.25rem;
  }
  h1 { font-size: 1.4rem; margin-bottom: 1rem; }
  h2 { font-size: 1.05rem; margin-bottom: .5rem; }
  p { font-size: .9rem; color: #555; margin-bottom: .75rem; line-height: 1.5; }
  .status { display: inline-block; font-size: .75rem; padding: .15rem .55rem; border-radius: 3px; font-weight: 600; }
  .status.on { background: #dff3e6; color: #1a7f4b; }
  .status.off { background: #f0f0f0; color: #888; }
  .message { font-size: .88rem; padding: .6rem .75rem; border-radius: 5px; margin-bottom: 1rem; background: #eef4ff; color: #2255aa; }
  .message.error { background: #fdf0ee; color: #a8362a; }
  .qr { text-align: center; margin: 1rem 0; }
  .qr svg { max-width: 220px; }
  code.value { display: block; word-break: break-all; background: #f7f7f7; padding: .5rem; border-radius: 4px; font-size: .8rem; margin: .5rem 0; }
  input[type=text] {
    width: 100%; padding: .6rem .75rem; border: 1px solid #ccc; border-radius: 5px;
    font-size: 1.1rem; letter-spacing: .1em; text-align: center; margin-bottom: .75rem;
  }
  button { padding: .6rem 1.1rem; background: #4f8ef7; color: #fff; border: none; border-radius: 5px; font-size: .9rem; cursor: pointer; }
  button.secondary { background: #eee; color: #444; margin-left: .5rem; }
  button:hover { filter: brightness(0.95); }
  .codes { background: #fffbe8; border: 1px solid #e8dca0; border-radius: 6px; padding: 1rem; margin-top: 1rem; }
  .codes ul { list-style: none; font-family: ui-monospace, monospace; font-size: .95rem; columns: 2; margin-top: .5rem; }
  .push-status { font-size: .85rem; color: #666; margin: .75rem 0; }
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
  .wrap, .footer { position: relative; z-index: 1; }
  <?php endif; ?>
</style>
<?php endif; ?>
</head>
<body>
<div class="wrap">
  <?php if ($b['logo_url']): ?>
  <img class="page-logo" src="<?= $b['logo_url'] ?>" alt="<?= $b['logo_alt'] ?>">
  <?php endif; ?>
  <h1>Two-Factor Authentication</h1>
  <?php if ($b['banner']): ?>
  <div class="page-banner"><?= $b['banner'] ?></div>
  <?php endif; ?>
  <?php if ($message): ?>
  <div class="message<?= $messageIsError ? ' error' : '' ?>">
    <?= htmlspecialchars($message, ENT_QUOTES) ?>
  </div>
  <?php endif; ?>

  <?php if (!empty($revealedCodes)): ?>
  <div class="codes">
    <strong>Save these backup codes now — they won't be shown again:</strong>
    <ul><?php foreach ($revealedCodes as $c): ?><li><?= htmlspecialchars($c, ENT_QUOTES) ?></li><?php endforeach; ?></ul>
  </div>
  <?php endif; ?>

  <div class="card">
    <h2>Authenticator app <span class="status <?= $totpEnrolled ? 'on' : 'off' ?>"><?= $totpEnrolled ? 'Enrolled' : 'Not set up' ?></span></h2>
    <?php if ($totpEnrolled): ?>
      <p>An authenticator app is confirmed for this account.</p>
    <?php elseif ($totpPending): ?>
      <p>Scan this with your authenticator app, then enter the current code to confirm.</p>
      <div class="qr">
        <?php if ($totpQr): ?><?= $totpQr ?><?php else: ?>
          <p><em>qrencode isn't installed on this server — enter this manually:</em></p>
        <?php endif; ?>
        <code class="value"><?= htmlspecialchars($totpUri, ENT_QUOTES) ?></code>
      </div>
      <form method="post">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES) ?>">
        <input type="hidden" name="action" value="verify_totp">
        <input type="text" name="code" maxlength="6" autofocus placeholder="6-digit code" autocomplete="one-time-code">
        <button type="submit">Confirm</button>
        <button type="submit" name="action" value="cancel_totp" class="secondary" formnovalidate>Cancel</button>
      </form>
    <?php else: ?>
      <form method="post">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES) ?>">
        <input type="hidden" name="action" value="start_totp">
        <button type="submit">Set up authenticator app</button>
      </form>
    <?php endif; ?>
  </div>

  <div class="card">
    <h2>Push notifications (ntfy) <span class="status <?= $ntfyEnrolled ? 'on' : 'off' ?>"><?= $ntfyEnrolled ? 'Enrolled' : 'Not set up' ?></span></h2>
    <?php if ($ntfyEnrolled): ?>
      <p>Sign-in push challenges are confirmed for this account.</p>
    <?php elseif ($ntfyPending): ?>
      <p>In the <strong>ntfy</strong> app, subscribe to this topic (scan or open the link), then reply to the
      notification already sent with the code it shows.</p>
      <div class="qr">
        <?php if ($ntfyQr): ?><?= $ntfyQr ?><?php else: ?>
          <p><em>qrencode isn't installed on this server — open this link on your phone:</em></p>
        <?php endif; ?>
        <code class="value"><?= htmlspecialchars($_SESSION['enroll_ntfy_url'], ENT_QUOTES) ?></code>
      </div>
      <div class="push-status" id="pushStatus">Waiting for your reply&hellip;</div>
      <form method="post">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES) ?>">
        <button type="submit" name="action" value="cancel_ntfy" class="secondary" formnovalidate>Cancel</button>
      </form>
      <script>
      (function () {
        var statusEl = document.getElementById('pushStatus');
        function poll() {
          fetch('mfa_enroll_check.php', { credentials: 'same-origin' })
            .then(function (r) { return r.json(); })
            .then(function (data) {
              if (data.status === 'confirmed') {
                location.reload();
              } else if (data.status === 'expired') {
                statusEl.textContent = 'That challenge expired — cancel and try again.';
              } else {
                setTimeout(poll, 2000);
              }
            })
            .catch(function () { setTimeout(poll, 3000); });
        }
        setTimeout(poll, 1500);
      })();
      </script>
    <?php else: ?>
      <form method="post">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES) ?>">
        <input type="hidden" name="action" value="start_ntfy">
        <button type="submit">Set up push notifications</button>
      </form>
    <?php endif; ?>
  </div>

  <div class="card">
    <h2>Backup codes <span class="status <?= $hasBackupCodes ? 'on' : 'off' ?>"><?= $hasBackupCodes ? 'Generated' : 'None yet' ?></span></h2>
    <p>Generated automatically the first time you confirm a method above, and shown once.
    Contact your administrator if you're locked out and have none left.</p>
  </div>

  <p><a href="<?= htmlspecialchars(dirname($_SERVER['PHP_SELF']), ENT_QUOTES) ?>/">&larr; Back</a></p>
</div>
<?php if ($b['footer']): ?>
<div class="footer"><?= $b['footer'] ?></div>
<?php endif; ?>
</body>
</html>
