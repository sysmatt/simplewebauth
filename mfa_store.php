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
 *
 * Merge rule: field-by-field, not record-by-record. If the main file defines
 * a field for a user at all, its value wins outright — even false/empty.
 * The local overlay only fills in fields the main file never mentions.
 */

require_once __DIR__ . '/mfa_config.php';

function mfa_users_file(): string {
    return defined('AUTH_USERS_FILE') ? AUTH_USERS_FILE : '/etc/simplewebauth/auth_users.php';
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
