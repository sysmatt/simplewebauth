<?php
/**
 * MFA data layer — shared by the web runtime (login.php, mfa_verify.php,
 * mfa_enroll.php) and the CLI (manage_users.php / authctl).
 *
 * Three files:
 *   - main file (AUTH_USERS_FILE)         — sysadmin/Ansible-managed, source
 *                                            of truth. Read-only to the web
 *                                            server. Format sniffed by
 *                                            extension: .ini or legacy
 *                                            scalar-string .php.
 *   - local overlay (AUTH_USERS_LOCAL_FILE)  — written by the web server
 *                                            itself on self-enrollment. Never
 *                                            contains password_hash.
 *   - burned-codes ledger (AUTH_BURNED_CODES_FILE) — one-time-use tracking
 *                                            for backup codes, per host.
 *   - login state (AUTH_LOGIN_STATE_FILE) — per-host failure counters,
 *                                            lockouts, and last accepted TOTP
 *                                            step (replay guard).
 *
 * Merge rule: field-by-field, not record-by-record. If the main file defines
 * a field for a user at all, its value wins outright — even false/empty.
 * The local overlay only fills in fields the main file never mentions.
 */

require_once __DIR__ . '/mfa_config.php';

function mfa_users_file(): string {
    if (defined('AUTH_USERS_FILE')) {
        return AUTH_USERS_FILE;
    }
    return is_file('/etc/simplewebauth/auth_users.ini')
        ? '/etc/simplewebauth/auth_users.ini'
        : '/etc/simplewebauth/auth_users.php';
}

// ---------------------------------------------------------------------
// Low-level ini parsing / rendering — user-record files (main + overlay)
// ---------------------------------------------------------------------

function mfa_normalize_ini_section(array $section): array {
    $rec = [];
    if (array_key_exists('password_hash', $section)) {
        $rec['password_hash'] = (string)$section['password_hash'];
    }
    if (array_key_exists('mfa_enabled', $section)) {
        $rec['mfa_enabled'] = strtolower(trim((string)$section['mfa_enabled'])) === 'true';
    }
    if (array_key_exists('totp_secret', $section)) {
        $rec['totp_secret'] = (string)$section['totp_secret'];
    }
    if (array_key_exists('ntfy_url', $section)) {
        $rec['ntfy_url'] = (string)$section['ntfy_url'];
    }
    if (array_key_exists('backup_codes', $section)) {
        $codes = $section['backup_codes'];
        $rec['backup_codes'] = array_values(is_array($codes) ? $codes : [$codes]);
    }
    if (array_key_exists('trust_device_days', $section)) {
        $rec['trust_device_days'] = (int)$section['trust_device_days'];
    }
    return $rec;
}

function mfa_read_ini_file(string $file): array {
    if (!is_file($file)) {
        return [];
    }
    $raw = parse_ini_file($file, true, INI_SCANNER_RAW);
    if ($raw === false) {
        return [];
    }
    $users = [];
    foreach ($raw as $username => $section) {
        $users[$username] = mfa_normalize_ini_section(is_array($section) ? $section : []);
    }
    return $users;
}

/**
 * None of our own generated values (bcrypt hashes, base32 secrets, safe-charset
 * codes, our own URLs) can ever contain a double quote — INI_SCANNER_RAW does
 * NOT unescape backslash sequences on read, only strips the wrapping quotes,
 * so a real escaping scheme would silently corrupt round-trips. Stripping is
 * the correct defense here, not escaping.
 */
function mfa_ini_safe(string $v): string {
    return str_replace(['"', "\n", "\r"], '', $v);
}

function mfa_render_ini_users(array $users): string {
    $lines = ["; managed by simplewebauth — safe to hand-edit while the service is stopped\n\n"];
    foreach ($users as $username => $rec) {
        $lines[] = '[' . $username . "]\n";
        if (array_key_exists('password_hash', $rec) && $rec['password_hash'] !== '') {
            $lines[] = 'password_hash = "' . mfa_ini_safe($rec['password_hash']) . "\"\n";
        }
        if (array_key_exists('mfa_enabled', $rec)) {
            $lines[] = 'mfa_enabled = ' . ($rec['mfa_enabled'] ? 'true' : 'false') . "\n";
        }
        if (!empty($rec['totp_secret'])) {
            $lines[] = 'totp_secret = "' . mfa_ini_safe($rec['totp_secret']) . "\"\n";
        }
        if (!empty($rec['ntfy_url'])) {
            $lines[] = 'ntfy_url = "' . mfa_ini_safe($rec['ntfy_url']) . "\"\n";
        }
        if (!empty($rec['backup_codes'])) {
            foreach ($rec['backup_codes'] as $hash) {
                $lines[] = 'backup_codes[] = "' . mfa_ini_safe($hash) . "\"\n";
            }
        }
        if (array_key_exists('trust_device_days', $rec)) {
            $lines[] = 'trust_device_days = ' . (int)$rec['trust_device_days'] . "\n";
        }
        $lines[] = "\n";
    }
    return implode('', $lines);
}

function mfa_atomic_write(string $file, string $contents): void {
    $dir = dirname($file);
    if (!is_dir($dir) && !@mkdir($dir, 0700, true)) {
        throw new RuntimeException("Cannot create directory: $dir");
    }
    $tmp = $file . '.tmp.' . getmypid() . '.' . bin2hex(random_bytes(4));
    if (file_put_contents($tmp, $contents) === false) {
        throw new RuntimeException("Cannot write temp file: $tmp");
    }
    chmod($tmp, 0600);
    if (!rename($tmp, $file)) {
        @unlink($tmp);
        throw new RuntimeException("Cannot move temp file into place: $file");
    }
}

function mfa_write_ini_file(string $file, array $users): void {
    mfa_atomic_write($file, mfa_render_ini_users($users));
}

/**
 * Holds an exclusive lock for the ENTIRE read-modify-write, so two workers
 * can't both read the old version and each apply a change with one clobbering
 * the other (a lost update) — the failure mode that actually matters here,
 * not the (much rarer) torn-write case that atomic rename alone prevents.
 * Same helper is used by the web runtime and by authctl/manage_users.php.
 */
function mfa_locked_update(string $file, callable $mutator): void {
    $dir = dirname($file);
    if (!is_dir($dir) && !@mkdir($dir, 0700, true)) {
        throw new RuntimeException("Cannot create directory: $dir");
    }
    $lockHandle = fopen($file . '.lock', 'c');
    if ($lockHandle === false || !flock($lockHandle, LOCK_EX)) {
        if (is_resource($lockHandle)) {
            fclose($lockHandle);
        }
        throw new RuntimeException("Cannot acquire lock for: $file");
    }
    try {
        $current = mfa_read_ini_file($file);
        $updated = $mutator($current);
        mfa_write_ini_file($file, $updated);
    } finally {
        flock($lockHandle, LOCK_UN);
        fclose($lockHandle);
    }
}

// ---------------------------------------------------------------------
// Main file — format-sniffed by extension (.ini vs legacy scalar .php)
// ---------------------------------------------------------------------

function mfa_load_main_users(): array {
    $file = mfa_users_file();
    if (preg_match('/\.ini$/i', $file)) {
        return mfa_read_ini_file($file);
    }
    // Legacy format: plain PHP array, 'username' => 'bcrypt_hash'. Never
    // carries MFA fields — installs get MFA the moment they migrate to .ini.
    if (!is_file($file)) {
        return [];
    }
    $data = require $file;
    if (!is_array($data)) {
        return [];
    }
    $users = [];
    foreach ($data as $username => $hash) {
        $users[$username] = ['password_hash' => (string)$hash];
    }
    return $users;
}

function mfa_load_local_users(): array {
    return mfa_read_ini_file(AUTH_USERS_LOCAL_FILE);
}

/**
 * Field-level merge for one user: null if the user doesn't exist in the main
 * file at all (the local overlay can never create a user on its own).
 */
function mfa_merged_user(string $username): ?array {
    $main = mfa_load_main_users();
    if (!isset($main[$username])) {
        return null;
    }
    $mainRec = $main[$username];
    $local = mfa_load_local_users();
    $localRec = $local[$username] ?? [];

    return [
        'password_hash' => $mainRec['password_hash'] ?? '',
        'mfa_enabled'   => array_key_exists('mfa_enabled', $mainRec) ? $mainRec['mfa_enabled'] : ($localRec['mfa_enabled'] ?? false),
        'totp_secret'   => array_key_exists('totp_secret', $mainRec) ? $mainRec['totp_secret'] : ($localRec['totp_secret'] ?? null),
        'ntfy_url'      => array_key_exists('ntfy_url', $mainRec) ? $mainRec['ntfy_url'] : ($localRec['ntfy_url'] ?? null),
        'backup_codes'  => array_key_exists('backup_codes', $mainRec) ? $mainRec['backup_codes'] : ($localRec['backup_codes'] ?? []),
        'trust_device_days' => array_key_exists('trust_device_days', $mainRec)
            ? $mainRec['trust_device_days']
            : ($localRec['trust_device_days'] ?? AUTH_MFA_TRUST_DEVICE_DAYS),
    ];
}

/**
 * Writes/merges fields into the local overlay for one user, and opportunistically
 * drops any field the main file already defines for that user in the same pass
 * (pruning only ever happens alongside a write that was already happening).
 */
function mfa_write_local_fields(string $username, array $fields): void {
    mfa_locked_update(AUTH_USERS_LOCAL_FILE, function (array $local) use ($username, $fields) {
        $main = mfa_load_main_users();
        $mainRec = $main[$username] ?? [];
        $merged = array_merge($local[$username] ?? [], $fields);
        foreach (array_keys($merged) as $field) {
            if (array_key_exists($field, $mainRec)) {
                unset($merged[$field]);
            }
        }
        if (!empty($merged)) {
            $local[$username] = $merged;
        } else {
            unset($local[$username]);
        }
        return $local;
    });
}

/** Drops any local-overlay field now redundant with the main file. Returns what was pruned. */
function mfa_prune_local(): array {
    $pruned = [];
    mfa_locked_update(AUTH_USERS_LOCAL_FILE, function (array $local) use (&$pruned) {
        $main = mfa_load_main_users();
        foreach ($local as $username => $rec) {
            $mainRec = $main[$username] ?? [];
            foreach (array_keys($rec) as $field) {
                if (array_key_exists($field, $mainRec)) {
                    unset($local[$username][$field]);
                    $pruned[] = "$username.$field";
                }
            }
            if (empty($local[$username])) {
                unset($local[$username]);
            }
        }
        return $local;
    });
    return $pruned;
}

/** Local-overlay fields that are still actually in effect (not shadowed by main) — for `authctl mfa pending`. */
function mfa_list_pending(): array {
    $local = mfa_load_local_users();
    $main = mfa_load_main_users();
    $pending = [];
    foreach ($local as $username => $rec) {
        $effective = [];
        foreach ($rec as $field => $value) {
            if (!array_key_exists($field, $main[$username] ?? [])) {
                $effective[$field] = $value;
            }
        }
        if (!empty($effective)) {
            $pending[$username] = $effective;
        }
    }
    return $pending;
}

function mfa_clear_local_user(string $username): bool {
    $existed = false;
    mfa_locked_update(AUTH_USERS_LOCAL_FILE, function (array $local) use ($username, &$existed) {
        if (isset($local[$username])) {
            $existed = true;
            unset($local[$username]);
        }
        return $local;
    });
    return $existed;
}

// ---------------------------------------------------------------------
// Burned backup-code ledger — per-host one-time-use enforcement
// ---------------------------------------------------------------------

function mfa_read_ledger(string $file): array {
    if (!is_file($file)) {
        return [];
    }
    $raw = parse_ini_file($file, true, INI_SCANNER_RAW);
    if ($raw === false) {
        return [];
    }
    $out = [];
    foreach ($raw as $username => $section) {
        $used = is_array($section) ? ($section['used'] ?? []) : [];
        $out[$username] = array_values(is_array($used) ? $used : [$used]);
    }
    return $out;
}

function mfa_render_ledger(array $ledger): string {
    $lines = ["; burned backup-code ledger — managed by simplewebauth\n\n"];
    foreach ($ledger as $username => $hashes) {
        if (empty($hashes)) {
            continue;
        }
        $lines[] = '[' . $username . "]\n";
        foreach ($hashes as $h) {
            $lines[] = 'used[] = "' . mfa_ini_safe($h) . "\"\n";
        }
        $lines[] = "\n";
    }
    return implode('', $lines);
}

function mfa_locked_update_ledger(string $file, callable $mutator): void {
    $dir = dirname($file);
    if (!is_dir($dir) && !@mkdir($dir, 0700, true)) {
        throw new RuntimeException("Cannot create directory: $dir");
    }
    $lockHandle = fopen($file . '.lock', 'c');
    if ($lockHandle === false || !flock($lockHandle, LOCK_EX)) {
        if (is_resource($lockHandle)) {
            fclose($lockHandle);
        }
        throw new RuntimeException("Cannot acquire lock for: $file");
    }
    try {
        $current = mfa_read_ledger($file);
        $updated = $mutator($current);
        mfa_atomic_write($file, mfa_render_ledger($updated));
    } finally {
        flock($lockHandle, LOCK_UN);
        fclose($lockHandle);
    }
}

/** Atomically checks-and-marks a code hash as used. Returns true only if THIS call was the one that burned it. */
function mfa_try_burn_code(string $username, string $hash): bool {
    $wasFresh = false;
    mfa_locked_update_ledger(AUTH_BURNED_CODES_FILE, function (array $ledger) use ($username, $hash, &$wasFresh) {
        $used = $ledger[$username] ?? [];
        if (in_array($hash, $used, true)) {
            $wasFresh = false;
            return $ledger;
        }
        $used[] = $hash;
        $ledger[$username] = $used;
        $wasFresh = true;
        return $ledger;
    });
    return $wasFresh;
}

// ---------------------------------------------------------------------
// Backup codes
// ---------------------------------------------------------------------

function mfa_generate_backup_codes(int $count = AUTH_MFA_BACKUP_CODE_COUNT, int $length = AUTH_MFA_BACKUP_CODE_LENGTH): array {
    $alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // excludes ambiguous 0/O, 1/I/L
    $codes = [];
    for ($i = 0; $i < $count; $i++) {
        $code = '';
        for ($j = 0; $j < $length; $j++) {
            $code .= $alphabet[random_int(0, strlen($alphabet) - 1)];
        }
        $codes[] = $code;
    }
    return $codes; // plaintext — caller shows these once, then hashes for storage
}

function mfa_hash_backup_codes(array $plaintextCodes): array {
    return array_map(
        fn($c) => password_hash($c, PASSWORD_BCRYPT, ['cost' => 12]),
        $plaintextCodes
    );
}

function mfa_normalize_backup_code(string $code): string {
    return strtoupper(trim($code));
}

/**
 * Verifies a submitted backup code against stored hashes and burns it
 * atomically on match (check-and-mark happen under one lock, so two
 * near-simultaneous submissions of the same code can't both succeed).
 */
function mfa_verify_backup_code(string $username, array $storedHashes, string $submittedCode): bool {
    $code = mfa_normalize_backup_code($submittedCode);
    foreach ($storedHashes as $hash) {
        if (password_verify($code, $hash)) {
            return mfa_try_burn_code($username, $hash);
        }
    }
    return false;
}

// ---------------------------------------------------------------------
// Trusted devices — "remember this device" ("skip MFA on this browser
// for N days"). One section per token, keyed by the token's SHA-256 hash
// (the token itself is 256 bits of CSPRNG output, not a human-guessable
// secret, so a fast hash is correct here — unlike backup codes, which use
// bcrypt specifically to resist offline brute force of a low-entropy value).
// ---------------------------------------------------------------------

function mfa_read_trusted_devices(string $file): array {
    if (!is_file($file)) {
        return [];
    }
    $raw = parse_ini_file($file, true, INI_SCANNER_RAW);
    if ($raw === false) {
        return [];
    }
    $out = [];
    foreach ($raw as $tokenHash => $section) {
        if (!is_array($section)) {
            continue;
        }
        $out[$tokenHash] = [
            'username' => (string)($section['username'] ?? ''),
            'expires'  => (int)($section['expires'] ?? 0),
        ];
    }
    return $out;
}

function mfa_render_trusted_devices(array $devices): string {
    $lines = ["; trusted-device ledger — managed by simplewebauth\n\n"];
    foreach ($devices as $tokenHash => $rec) {
        $lines[] = '[' . $tokenHash . "]\n";
        $lines[] = 'username = "' . mfa_ini_safe($rec['username']) . "\"\n";
        $lines[] = 'expires = ' . (int)$rec['expires'] . "\n\n";
    }
    return implode('', $lines);
}

function mfa_locked_update_trusted_devices(string $file, callable $mutator): void {
    $dir = dirname($file);
    if (!is_dir($dir) && !@mkdir($dir, 0700, true)) {
        throw new RuntimeException("Cannot create directory: $dir");
    }
    $lockHandle = fopen($file . '.lock', 'c');
    if ($lockHandle === false || !flock($lockHandle, LOCK_EX)) {
        if (is_resource($lockHandle)) {
            fclose($lockHandle);
        }
        throw new RuntimeException("Cannot acquire lock for: $file");
    }
    try {
        $current = mfa_read_trusted_devices($file);
        $updated = $mutator($current);
        mfa_atomic_write($file, mfa_render_trusted_devices($updated));
    } finally {
        flock($lockHandle, LOCK_UN);
        fclose($lockHandle);
    }
}

/** Issues a new trust token for $username, valid $days days. Returns the plaintext token (for the cookie) — only its hash is ever stored. */
function mfa_issue_trust_token(string $username, int $days): string {
    $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $hash = hash('sha256', $token);
    $expires = time() + ($days * 86400);
    mfa_locked_update_trusted_devices(AUTH_TRUSTED_DEVICES_FILE, function (array $devices) use ($hash, $username, $expires) {
        $devices[$hash] = ['username' => $username, 'expires' => $expires];
        return $devices;
    });
    return $token;
}

/** True if $token is a valid, unexpired trust token issued for exactly $username. */
function mfa_check_trust_token(string $username, string $token): bool {
    if ($token === '') {
        return false;
    }
    $devices = mfa_read_trusted_devices(AUTH_TRUSTED_DEVICES_FILE);
    $rec = $devices[hash('sha256', $token)] ?? null;
    if ($rec === null) {
        return false;
    }
    return $rec['username'] === $username && $rec['expires'] > time();
}

/** Revokes every trusted device for $username (lost/stolen device, `authctl mfa untrust`). Returns count removed. */
function mfa_revoke_trust_devices(string $username): int {
    $removed = 0;
    mfa_locked_update_trusted_devices(AUTH_TRUSTED_DEVICES_FILE, function (array $devices) use ($username, &$removed) {
        foreach ($devices as $hash => $rec) {
            if ($rec['username'] === $username) {
                unset($devices[$hash]);
                $removed++;
            }
        }
        return $devices;
    });
    return $removed;
}

/** Housekeeping — drops expired entries regardless of user. Returns count removed. */
function mfa_prune_expired_trust_devices(): int {
    $removed = 0;
    mfa_locked_update_trusted_devices(AUTH_TRUSTED_DEVICES_FILE, function (array $devices) use (&$removed) {
        $now = time();
        foreach ($devices as $hash => $rec) {
            if ($rec['expires'] <= $now) {
                unset($devices[$hash]);
                $removed++;
            }
        }
        return $devices;
    });
    return $removed;
}

/** Issues a token and sets the browser cookie in one step — the only entry point mfa_verify.php/mfa_check.php should use. */
function mfa_set_trust_cookie(string $username, int $days): void {
    $token = mfa_issue_trust_token($username, $days);
    $secure = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    setcookie(AUTH_MFA_TRUST_COOKIE_NAME, $token, [
        'expires'  => time() + ($days * 86400),
        'path'     => '/',
        'secure'   => $secure,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

// ---------------------------------------------------------------------
// Login state — per-account brute-force lockout + TOTP replay guard, per
// host. One section per username; only usernames that exist in the users
// file are ever written, so junk usernames can't grow the file.
//   fail_count / fail_first — failures in the current AUTH_LOCKOUT_WINDOW
//   locked_until            — unix time the lockout ends (absent = unlocked)
//   totp_last_step          — last TOTP time step accepted for sign-in
// ---------------------------------------------------------------------

const AUTH_LOGIN_STATE_FIELDS = ['fail_count', 'fail_first', 'locked_until', 'totp_last_step'];

function mfa_read_login_state(string $file): array {
    if (!is_file($file)) {
        return [];
    }
    $raw = parse_ini_file($file, true, INI_SCANNER_RAW);
    if ($raw === false) {
        return [];
    }
    $out = [];
    foreach ($raw as $username => $section) {
        if (!is_array($section)) {
            continue;
        }
        $rec = [];
        foreach (AUTH_LOGIN_STATE_FIELDS as $f) {
            if (isset($section[$f])) {
                $rec[$f] = (int)$section[$f];
            }
        }
        $out[(string)$username] = $rec;
    }
    return $out;
}

function mfa_render_login_state(array $state): string {
    $lines = ["; login state (failure counters, lockouts, TOTP replay guard) — managed by simplewebauth\n\n"];
    foreach ($state as $username => $rec) {
        $rec = array_intersect_key($rec, array_flip(AUTH_LOGIN_STATE_FIELDS));
        if (empty($rec)) {
            continue;
        }
        $lines[] = '[' . $username . "]\n";
        foreach ($rec as $f => $v) {
            $lines[] = $f . ' = ' . (int)$v . "\n";
        }
        $lines[] = "\n";
    }
    return implode('', $lines);
}

function mfa_locked_update_login_state(callable $mutator): void {
    $file = AUTH_LOGIN_STATE_FILE;
    $dir = dirname($file);
    if (!is_dir($dir) && !@mkdir($dir, 0700, true)) {
        throw new RuntimeException("Cannot create directory: $dir");
    }
    $lockHandle = fopen($file . '.lock', 'c');
    if ($lockHandle === false || !flock($lockHandle, LOCK_EX)) {
        if (is_resource($lockHandle)) {
            fclose($lockHandle);
        }
        throw new RuntimeException("Cannot acquire lock for: $file");
    }
    try {
        $current = mfa_read_login_state($file);
        $updated = $mutator($current);
        if ($updated !== $current) {
            mfa_atomic_write($file, mfa_render_login_state($updated));
        }
    } finally {
        flock($lockHandle, LOCK_UN);
        fclose($lockHandle);
    }
}

/** True while $username is locked out. Lock-free read — writes are atomic renames. */
function auth_lockout_active(string $username): bool {
    $rec = mfa_read_login_state(AUTH_LOGIN_STATE_FILE)[$username] ?? [];
    return ($rec['locked_until'] ?? 0) > time();
}

/**
 * Counts one failure (wrong password, or any MFA strike) against $username and
 * locks the account once AUTH_LOCKOUT_MAX_FAILURES land within
 * AUTH_LOCKOUT_WINDOW. Returns true if the account is locked after this call.
 *
 * Fails OPEN on a storage error (logged): a missing/unwritable state dir must
 * not take down sign-in for hosts on the legacy .php users file. The nginx
 * rate limit still applies in that case.
 */
function auth_record_failure(string $username): bool {
    $locked = false;
    try {
        mfa_locked_update_login_state(function (array $state) use ($username, &$locked) {
            $now = time();
            $rec = $state[$username] ?? [];
            if (($rec['locked_until'] ?? 0) > $now) {
                $locked = true;   // already locked — don't extend it
                return $state;
            }
            unset($rec['locked_until']);
            if (($rec['fail_first'] ?? 0) + AUTH_LOCKOUT_WINDOW <= $now) {
                $rec['fail_count'] = 0;
                $rec['fail_first'] = $now;
            }
            $rec['fail_count'] = ($rec['fail_count'] ?? 0) + 1;
            if ($rec['fail_count'] >= AUTH_LOCKOUT_MAX_FAILURES) {
                $rec['locked_until'] = $now + AUTH_LOCKOUT_DURATION;
                unset($rec['fail_count'], $rec['fail_first']);
                $locked = true;
                error_log("simplewebauth: account '$username' locked for " . AUTH_LOCKOUT_DURATION
                    . "s after " . AUTH_LOCKOUT_MAX_FAILURES . " failed sign-in attempts");
            }
            $state[$username] = $rec;
            return $state;
        });
    } catch (RuntimeException $e) {
        error_log('simplewebauth: cannot record login failure: ' . $e->getMessage());
    }
    return $locked;
}

/** Clears failure counters after a COMPLETE sign-in. Leaves totp_last_step alone. Fails open (logged). */
function auth_clear_failures(string $username): void {
    $rec = mfa_read_login_state(AUTH_LOGIN_STATE_FILE)[$username] ?? [];
    if (!isset($rec['fail_count']) && !isset($rec['fail_first']) && !isset($rec['locked_until'])) {
        return;   // nothing to clear — skip the write on the common path
    }
    try {
        mfa_locked_update_login_state(function (array $state) use ($username) {
            unset($state[$username]['fail_count'], $state[$username]['fail_first'], $state[$username]['locked_until']);
            return $state;
        });
    } catch (RuntimeException $e) {
        error_log('simplewebauth: cannot clear login failures: ' . $e->getMessage());
    }
}

/** Admin unlock (`authctl unlock`). Returns true if the user had a lockout or failures recorded. */
function auth_unlock(string $username): bool {
    $had = false;
    mfa_locked_update_login_state(function (array $state) use ($username, &$had) {
        $rec = $state[$username] ?? [];
        $had = isset($rec['fail_count']) || isset($rec['locked_until']);
        unset($state[$username]['fail_count'], $state[$username]['fail_first'], $state[$username]['locked_until']);
        return $state;
    });
    return $had;
}

/** Usernames with a lockout or failures in the current window, for `authctl locked`. */
function auth_list_lockouts(): array {
    $now = time();
    $out = [];
    foreach (mfa_read_login_state(AUTH_LOGIN_STATE_FILE) as $username => $rec) {
        $lockedUntil = $rec['locked_until'] ?? 0;
        $inWindow = ($rec['fail_first'] ?? 0) + AUTH_LOCKOUT_WINDOW > $now;
        if ($lockedUntil > $now || (($rec['fail_count'] ?? 0) > 0 && $inWindow)) {
            $out[$username] = [
                'locked_until' => $lockedUntil > $now ? $lockedUntil : 0,
                'fail_count'   => $inWindow ? ($rec['fail_count'] ?? 0) : 0,
            ];
        }
    }
    return $out;
}

/**
 * Atomically accepts TOTP time step $step for $username only if it is newer
 * than the last one accepted, then records it. Returns false for a replay
 * (same code again, or an older code within the drift window). Fails CLOSED
 * — throws on storage error, same as the backup-code ledger.
 */
function mfa_totp_claim_step(string $username, int $step): bool {
    $fresh = false;
    mfa_locked_update_login_state(function (array $state) use ($username, $step, &$fresh) {
        if ($step <= ($state[$username]['totp_last_step'] ?? PHP_INT_MIN)) {
            return $state;
        }
        $state[$username]['totp_last_step'] = $step;
        $fresh = true;
        return $state;
    });
    return $fresh;
}
