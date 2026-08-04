<?php
/**
 * MFA configuration constants. Required by mfa_store.php (and transitively by
 * every MFA-aware entry point). All overridable by defining the constant
 * before requiring this file, same convention as auth.php.
 */

if (!defined('AUTH_USERS_LOCAL_FILE')) {
    define('AUTH_USERS_LOCAL_FILE', '/var/local/simplewebauth/auth_users_local.ini');
}

if (!defined('AUTH_BURNED_CODES_FILE')) {
    define('AUTH_BURNED_CODES_FILE', '/var/local/simplewebauth/burned_codes_local.ini');
}

// Self-service MFA enrollment (mfa_enroll.php) is off unless a deployment
// opts in — pure vault/Ansible-provisioned fleets see no change at all.
if (!defined('AUTH_ALLOW_SELF_MFA')) {
    define('AUTH_ALLOW_SELF_MFA', false);
}

// Default server used only when self-enrollment mints a *new* ntfy topic.
// Never consulted at verify time — the stored ntfy_url is self-contained.
if (!defined('AUTH_NTFY_SERVER')) {
    define('AUTH_NTFY_SERVER', 'https://ntfy.sh');
}

// How long a password-verified, second-factor-pending session stays valid.
if (!defined('AUTH_MFA_PENDING_LIFETIME')) {
    define('AUTH_MFA_PENDING_LIFETIME', 300); // 5 minutes
}

// Shared strike counter across ALL methods (wrong code, wrong/timed-out ntfy
// reply). Hitting this clears the pending session entirely.
if (!defined('AUTH_MFA_MAX_ATTEMPTS')) {
    define('AUTH_MFA_MAX_ATTEMPTS', 3);
}

// How long an ntfy challenge stays valid before a timeout counts as a strike.
if (!defined('AUTH_MFA_NTFY_CHALLENGE_TTL')) {
    define('AUTH_MFA_NTFY_CHALLENGE_TTL', 90);
}

if (!defined('AUTH_MFA_BACKUP_CODE_COUNT')) {
    define('AUTH_MFA_BACKUP_CODE_COUNT', 10);
}

if (!defined('AUTH_MFA_BACKUP_CODE_LENGTH')) {
    define('AUTH_MFA_BACKUP_CODE_LENGTH', 10);
}

if (!defined('AUTH_TRUSTED_DEVICES_FILE')) {
    define('AUTH_TRUSTED_DEVICES_FILE', '/var/local/simplewebauth/trusted_devices_local.ini');
}

// Default "remember this device" duration. Overridable per-user via the
// trust_device_days ini field — 0 disables the feature for that user
// entirely (checked live at login time, not just at issuance).
if (!defined('AUTH_MFA_TRUST_DEVICE_DAYS')) {
    define('AUTH_MFA_TRUST_DEVICE_DAYS', 60);
}

if (!defined('AUTH_MFA_TRUST_COOKIE_NAME')) {
    define('AUTH_MFA_TRUST_COOKIE_NAME', 'phpauth_trust');
}
