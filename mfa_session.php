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

/**
 * Post-login redirect allowlist. Returns $url only if it stays on this site,
 * otherwise '/'. Accepted:
 *   - a path starting with exactly one '/' (not '//' — protocol-relative), or
 *   - an absolute http(s) URL whose host and port match this request's Host,
 *     with no user:pass@ part (auth.php and nginx's login redirect send these).
 * Anything else — javascript:/data: URLs, 'http:evil.com', backslashes
 * (browsers read '/\evil.com' as '//evil.com'), control characters or spaces
 * (browsers strip tabs/newlines, so '/<TAB>/evil.com' becomes '//evil.com') —
 * falls back to '/'. Used when the value is accepted (login.php) AND again
 * where it is consumed (mfa_verify.php, mfa_check.php).
 */
function safe_redirect(string $url): string {
    if ($url === '' || preg_match('/[\x00-\x20\x7f\\\\]/', $url)) {
        return '/';
    }

    if ($url[0] === '/') {
        return ($url[1] ?? '') === '/' ? '/' : $url;
    }

    $parts = parse_url($url);
    $scheme = strtolower($parts['scheme'] ?? '');
    if (
        $parts === false
        || !in_array($scheme, ['http', 'https'], true)
        || strncasecmp($url, $scheme . '://', strlen($scheme) + 3) !== 0
        || !isset($parts['host'])
        || isset($parts['user']) || isset($parts['pass'])
    ) {
        return '/';
    }

    // Compare host + port against this request's Host header. A port equal to
    // the scheme default is treated as absent, as browsers do.
    $defaults = ['http' => 80, 'https' => 443];
    $urlPort = isset($parts['port']) && $parts['port'] !== $defaults[$scheme] ? (string)$parts['port'] : '';
    if (!preg_match('/^(\[[^\]]+\]|[^:\[\]]+)(?::(\d+))?$/', strtolower($_SERVER['HTTP_HOST'] ?? ''), $m)) {
        return '/';
    }
    $curPort = (isset($m[2]) && !in_array((int)$m[2], [80, 443], true)) ? $m[2] : '';

    return (strtolower($parts['host']) === $m[1] && $urlPort === $curPort) ? $url : '/';
}

/** Computes the web-relative path to a sibling entry-point file, same convention auth.php/login.php use. */
function mfa_relative_url(string $filename): string {
    $abs = realpath(__DIR__ . '/' . $filename);
    $docRoot = rtrim($_SERVER['DOCUMENT_ROOT'], '/');
    return str_replace($docRoot, '', $abs);
}
