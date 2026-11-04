<?php
/**
 * CLI user manager for auth_users.php / auth_users.ini
 *
 * Usage:
 *   php manage_users.php list
 *   php manage_users.php add <username> <password>
 *   php manage_users.php remove <username>
 *   php manage_users.php passwd <username> <newpassword>
 *   php manage_users.php migrate [target.ini]
 *   php manage_users.php mfa new <username>
 *   php manage_users.php mfa pending
 *   php manage_users.php mfa merge
 *   php manage_users.php mfa disable <username>
 *   php manage_users.php mfa untrust <username>
 *   php manage_users.php locked
 *   php manage_users.php unlock <username>
 */

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    exit('CLI only.');
}

require_once __DIR__ . '/mfa_store.php';
require_once __DIR__ . '/mfa_totp.php';
require_once __DIR__ . '/mfa_ntfy.php';
require_once __DIR__ . '/mfa_qr.php';

$usersFile = defined('AUTH_USERS_FILE') ? AUTH_USERS_FILE : (
    is_file('/etc/simplewebauth/auth_users.ini')
        ? '/etc/simplewebauth/auth_users.ini'
        : '/etc/simplewebauth/auth_users.php'
);

function ensure_users_dir(string $file): void {
    $dir = dirname($file);
    if (is_dir($dir)) return;
    if (!@mkdir($dir, 0750, true)) {
        fwrite(STDERR, "Cannot create $dir — try running with sudo\n");
        exit(1);
    }
}

/** Full per-user records regardless of format — legacy .php yields password_hash only. */
function load_users(string $file): array {
    if (preg_match('/\.ini$/i', $file)) {
        return mfa_read_ini_file($file);
    }
    if (!file_exists($file)) return [];
    $data = require $file;
    if (!is_array($data)) return [];
    $users = [];
    foreach ($data as $u => $hash) {
        $users[$u] = ['password_hash' => (string)$hash];
    }
    return $users;
}

function save_users(string $file, array $users): void {
    ensure_users_dir($file);
    if (preg_match('/\.ini$/i', $file)) {
        mfa_write_ini_file($file, $users);
        return;
    }
    // Legacy scalar format — only password_hash can ever be persisted here.
    $lines = ["<?php\n// User database — managed by manage_users.php\n\nreturn [\n"];
    foreach ($users as $u => $rec) {
        $eu = addslashes($u);
        $eh = addslashes($rec['password_hash'] ?? '');
        $lines[] = "    '$eu' => '$eh',\n";
    }
    $lines[] = "];\n";
    file_put_contents($file, implode('', $lines));
}

function hash_password(string $password): string {
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

function prompt_password(string $prompt): string {
    echo $prompt;
    system('stty -echo');
    $pass = trim(fgets(STDIN));
    system('stty echo');
    echo "\n";
    return $pass;
}

$cmd = $argv[1] ?? 'help';

switch ($cmd) {
    case 'list':
        $users = load_users($usersFile);
        if (empty($users)) {
            echo "No users configured.\n";
        } else {
            echo "Users:\n";
            foreach ($users as $u => $rec) {
                $mfaTag = !empty($rec['mfa_enabled']) ? ' [mfa]' : '';
                echo "  - $u$mfaTag\n";
            }
        }
        break;

    case 'add':
        $username = $argv[2] ?? '';
        if ($username === '') { echo "Usage: php manage_users.php add <username> [password]\n"; exit(1); }
        $users = load_users($usersFile);
        if (isset($users[$username])) { echo "User '$username' already exists. Use 'passwd' to change password.\n"; exit(1); }
        $password = $argv[3] ?? prompt_password("Password for $username: ");
        if (strlen($password) < 8) { echo "Password must be at least 8 characters.\n"; exit(1); }
        $users[$username] = ['password_hash' => hash_password($password)];
        save_users($usersFile, $users);
        echo "Added user '$username'.\n";
        break;

    case 'remove':
    case 'rm':
    case 'del':
        $username = $argv[2] ?? '';
        if ($username === '') { echo "Usage: php manage_users.php remove <username>\n"; exit(1); }
        $users = load_users($usersFile);
        if (!isset($users[$username])) { echo "User '$username' not found.\n"; exit(1); }
        unset($users[$username]);
        save_users($usersFile, $users);
        mfa_clear_local_user($username); // drop any orphaned self-enrolled MFA data too
        echo "Removed user '$username'.\n";
        break;

    case 'passwd':
        $username = $argv[2] ?? '';
        if ($username === '') { echo "Usage: php manage_users.php passwd <username> [newpassword]\n"; exit(1); }
        $users = load_users($usersFile);
        if (!isset($users[$username])) { echo "User '$username' not found. Use 'add' to create.\n"; exit(1); }
        $password = $argv[3] ?? prompt_password("New password for $username: ");
        if (strlen($password) < 8) { echo "Password must be at least 8 characters.\n"; exit(1); }
        $users[$username]['password_hash'] = hash_password($password); // preserves any MFA fields already on the record
        save_users($usersFile, $users);
        echo "Password updated for '$username'.\n";
        break;

    case 'migrate':
        if (preg_match('/\.ini$/i', $usersFile)) {
            echo "$usersFile is already an .ini file — nothing to migrate.\n";
            exit(1);
        }
        $target = $argv[2] ?? (dirname($usersFile) . '/auth_users.ini');
        if (file_exists($target)) {
            echo "Target already exists: $target — remove or choose a different path first.\n";
            exit(1);
        }
        $users = load_users($usersFile); // legacy reader — password_hash only, exactly as today
        save_users($target, $users);
        echo "Migrated " . count($users) . " user(s) to $target\n\n";
        echo "Next steps:\n";
        echo "  1. Update AUTH_USERS_FILE in your auth.php/login.php (define it before requiring auth.php),\n";
        echo "     and authctl's USERS_FILE variable, to point at:\n";
        echo "       $target\n";
        echo "  2. The original $usersFile is left in place untouched — remove it once you've confirmed\n";
        echo "     the new file works.\n";
        echo "  3. MFA (authctl mfa new / self-enrollment) only works against the .ini format.\n";
        break;

    case 'mfa':
        $sub = $argv[2] ?? '';
        switch ($sub) {
            case 'new':
                $username = $argv[3] ?? '';
                if ($username === '') { echo "Usage: php manage_users.php mfa new <username>\n"; exit(1); }
                $users = load_users($usersFile);
                if (!isset($users[$username])) { echo "User '$username' not found. Use 'add' to create it first.\n"; exit(1); }

                $totpSecret = totp_generate_secret();
                $totpUri = totp_provisioning_uri($totpSecret, $username, 'SimpleWebAuth');
                $ntfyUrl = ntfy_generate_topic_url(AUTH_NTFY_SERVER);
                $plainCodes = mfa_generate_backup_codes();
                $hashedCodes = mfa_hash_backup_codes($plainCodes);

                echo "=== TOTP — scan with an authenticator app ===\n";
                echo (qr_render($totpUri, 'ANSIUTF8') ?? "(install qrencode for a terminal QR code)\n");
                echo "otpauth URI: $totpUri\n\n";

                echo "=== ntfy push — subscribe from the ntfy app ===\n";
                echo (qr_render($ntfyUrl, 'ANSIUTF8') ?? "(install qrencode for a terminal QR code)\n");
                echo "Topic URL: $ntfyUrl\n\n";

                echo "=== Backup codes — shown once, store these securely (e.g. in vault) ===\n";
                foreach ($plainCodes as $c) { echo "  $c\n"; }
                echo "\n";

                echo "=== Paste into your vault-managed $usersFile ===\n";
                echo "Complete section, including the existing password_hash — replace this\n";
                echo "user's [$username] section entirely, don't add a second one (a duplicate\n";
                echo "section silently drops whichever fields were only in the first).\n\n";
                echo mfa_render_ini_users([$username => array_merge($users[$username], [
                    'mfa_enabled'   => true,
                    'totp_secret'   => $totpSecret,
                    'ntfy_url'      => $ntfyUrl,
                    'backup_codes'  => $hashedCodes,
                ])]);
                echo "\nNothing was written to disk — this only prints to your terminal.\n";
                break;

            case 'pending':
                $pending = mfa_list_pending();
                if (empty($pending)) {
                    echo "No self-enrolled MFA data awaiting capture.\n";
                    break;
                }
                $mainUsers = load_users($usersFile);
                foreach ($pending as $username => $fields) {
                    $rec = array_merge(['password_hash' => $mainUsers[$username]['password_hash'] ?? ''], $fields);
                    echo "--- $username ---\n";
                    echo mfa_render_ini_users([$username => $rec]) . "\n";
                }
                echo "Paste the stanza(s) above into your vault-managed source, then push.\n";
                break;

            case 'merge':
                $pruned = mfa_prune_local();
                if (empty($pruned)) {
                    echo "Nothing to prune — the local overlay has no fields already defined centrally.\n";
                } else {
                    echo "Pruned (now defined centrally, so no longer needed locally):\n";
                    foreach ($pruned as $p) { echo "  - $p\n"; }
                }
                $expired = mfa_prune_expired_trust_devices();
                echo $expired > 0
                    ? "Pruned $expired expired trusted-device entr" . ($expired === 1 ? 'y' : 'ies') . ".\n"
                    : "No expired trusted-device entries to prune.\n";
                break;

            case 'disable':
                $username = $argv[3] ?? '';
                if ($username === '') { echo "Usage: php manage_users.php mfa disable <username>\n"; exit(1); }
                if (mfa_clear_local_user($username)) {
                    echo "Cleared self-enrolled MFA data for '$username' from the local overlay.\n";
                } else {
                    echo "No self-enrolled MFA data found for '$username' in the local overlay.\n";
                    echo "If MFA is enabled centrally (in $usersFile), disable it there instead\n";
                    echo "(e.g. set mfa_enabled = false) and push.\n";
                }
                break;

            case 'untrust':
                $username = $argv[3] ?? '';
                if ($username === '') { echo "Usage: php manage_users.php mfa untrust <username>\n"; exit(1); }
                $removed = mfa_revoke_trust_devices($username);
                echo $removed > 0
                    ? "Revoked $removed trusted device(s) for '$username'.\n"
                    : "No trusted devices found for '$username'.\n";
                break;

            default:
                echo <<<HELP
manage_users.php mfa — MFA management

Commands:
  mfa new <username>     Generate a TOTP secret, ntfy topic, and backup codes
                         for offline/vault provisioning. Prints only — writes
                         nothing to disk.
  mfa pending            List self-enrolled MFA data not yet captured into
                         the vault-managed main file, ready to paste.
  mfa merge              Prune local-overlay fields now redundant with the
                         main file, and expired trusted-device entries.
                         Safe to run anytime.
  mfa disable <username> Clear self-enrolled MFA data for a user.
  mfa untrust <username> Revoke all "remembered devices" for a user (lost
                         or stolen device, etc.).

HELP;
        }
        break;

    case 'locked':
        $rows = auth_list_lockouts();
        if (empty($rows)) {
            echo "No locked accounts or recent failures.\n";
            break;
        }
        foreach ($rows as $u => $r) {
            echo $r['locked_until'] > 0
                ? sprintf("%-20s LOCKED until %s\n", $u, date('Y-m-d H:i:s', $r['locked_until']))
                : sprintf("%-20s %d recent failure(s)\n", $u, $r['fail_count']);
        }
        break;

    case 'unlock':
        $username = $argv[2] ?? '';
        if ($username === '') { echo "Usage: php manage_users.php unlock <username>\n"; exit(1); }
        echo auth_unlock($username)
            ? "Cleared lockout/failures for '$username'.\n"
            : "No lockout or failures recorded for '$username'.\n";
        break;

    default:
        echo <<<HELP
manage_users.php — auth_users manager

Commands:
  list                          List all users
  add <username> [password]     Add a new user
  remove <username>             Remove a user (aliases: rm, del)
  passwd <username> [password]  Change a user's password
  migrate [target.ini]          Convert legacy auth_users.php to .ini format
  mfa <subcommand>               MFA management — run 'mfa' with no args for help
  locked                        List locked accounts and recent failures
  unlock <username>             Clear a lockout and failure count

HELP;
}
