<?php
/**
 * Shared pending-MFA session helpers — used by mfa_verify.php and mfa_check.php.
 *
 * PHP's default session handler holds an exclusive lock on the session data
 * for the life of a request, so concurrent requests against the same session
 * (a form POST racing the background ntfy poll) are naturally serialized —
 * no extra locking needed here beyond what session_start() already gives us.
 */

require_once __DIR__ . '/mfa_config.php';

function mfa_clear_pending_session(): void {
    unset(
        $_SESSION['mfa_pending_user'],
        $_SESSION['mfa_pending_since'],
        $_SESSION['mfa_pending_redirect'],
        $_SESSION['mfa_pending_strikes'],
        $_SESSION['mfa_ntfy_challenge'],
        $_SESSION['mfa_ntfy_since'],
        $_SESSION['mfa_ntfy_expired_counted'],
        $_SESSION['mfa_csrf_token']
    );
}

function mfa_pending_active(): bool {
    return !empty($_SESSION['mfa_pending_user']) && !empty($_SESSION['mfa_pending_since']);
}

function mfa_pending_expired(): bool {
    return (time() - ($_SESSION['mfa_pending_since'] ?? 0)) > AUTH_MFA_PENDING_LIFETIME;
}

/** Registers one strike against the shared counter. Returns true if strikes are now exhausted. */
function mfa_register_strike(): bool {
    $_SESSION['mfa_pending_strikes'] = ($_SESSION['mfa_pending_strikes'] ?? 0) + 1;
    return $_SESSION['mfa_pending_strikes'] >= AUTH_MFA_MAX_ATTEMPTS;
}

/** Computes the web-relative path to a sibling entry-point file, same convention auth.php/login.php use. */
function mfa_relative_url(string $filename): string {
    $abs = realpath(__DIR__ . '/' . $filename);
    $docRoot = rtrim($_SERVER['DOCUMENT_ROOT'], '/');
    return str_replace($docRoot, '', $abs);
}
