<?php
/**
 * JSON polling endpoint for mfa_enroll.php's ntfy proof-of-possession step.
 * Never called directly by a user — only by the enrollment page's own JS.
 */

require __DIR__ . '/auth.php';

if (!AUTH_ALLOW_SELF_MFA) {
    http_response_code(403);
    exit;
}

require_once AUTH_DIR . '/mfa_store.php';
require_once AUTH_DIR . '/mfa_ntfy.php';

header('Content-Type: application/json');

function enroll_check_respond(array $data): void {
    echo json_encode($data);
    exit;
}

if (empty($_SESSION['enroll_ntfy_url']) || empty($_SESSION['enroll_ntfy_challenge'])) {
    enroll_check_respond(['status' => 'idle']);
}

$topic = $_SESSION['enroll_ntfy_url'];
$challenge = $_SESSION['enroll_ntfy_challenge'];
$since = (int)$_SESSION['enroll_ntfy_since'];

// 5s backdate cushion for clock skew between this server and ntfy's own timestamps.
if (ntfy_check_challenge($topic, $challenge, $since - 5)) {
    $username = auth_user();
    $user = mfa_merged_user($username);

    if (empty($user['backup_codes'])) {
        $plain = mfa_generate_backup_codes();
        mfa_write_local_fields($username, ['backup_codes' => mfa_hash_backup_codes($plain)]);
        $_SESSION['enroll_reveal_codes'] = $plain; // shown once, on the reloaded page
    }
    mfa_write_local_fields($username, ['mfa_enabled' => true, 'ntfy_url' => $topic]);
    unset($_SESSION['enroll_ntfy_url'], $_SESSION['enroll_ntfy_challenge'], $_SESSION['enroll_ntfy_since']);
    enroll_check_respond(['status' => 'confirmed']);
}

$elapsed = time() - $since;
if ($elapsed > AUTH_MFA_NTFY_CHALLENGE_TTL) {
    unset($_SESSION['enroll_ntfy_url'], $_SESSION['enroll_ntfy_challenge'], $_SESSION['enroll_ntfy_since']);
    enroll_check_respond(['status' => 'expired']);
}

enroll_check_respond(['status' => 'waiting']);
