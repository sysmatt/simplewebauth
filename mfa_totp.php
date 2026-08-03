<?php
/**
 * RFC 6238 TOTP — no external dependencies, HMAC-SHA1 + base32 only.
 */

define('TOTP_PERIOD', 30);
define('TOTP_DIGITS', 6);

function totp_generate_secret(int $bytes = 20): string {
    return totp_base32_encode(random_bytes($bytes));
}

function totp_base32_encode(string $data): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    for ($i = 0; $i < strlen($data); $i++) {
        $bits .= str_pad(decbin(ord($data[$i])), 8, '0', STR_PAD_LEFT);
    }
    $output = '';
    foreach (str_split($bits, 5) as $chunk) {
        if (strlen($chunk) < 5) {
            $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
        }
        $output .= $alphabet[bindec($chunk)];
    }
    return $output;
}

function totp_base32_decode(string $secret): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $secret = strtoupper(preg_replace('/[^A-Za-z2-7]/', '', $secret));
    $bits = '';
    for ($i = 0; $i < strlen($secret); $i++) {
        $pos = strpos($alphabet, $secret[$i]);
        if ($pos === false) continue;
        $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
    }
    $bytes = '';
    foreach (str_split($bits, 8) as $byteBits) {
        if (strlen($byteBits) < 8) break; // trailing padding bits, discard
        $bytes .= chr(bindec($byteBits));
    }
    return $bytes;
}

/** Builds an otpauth://totp/ URI suitable for QR enrollment. */
function totp_provisioning_uri(string $secret, string $accountName, string $issuer): string {
    $label = rawurlencode($issuer) . ':' . rawurlencode($accountName);
    $query = http_build_query([
        'secret'    => $secret,
        'issuer'    => $issuer,
        'algorithm' => 'SHA1',
        'digits'    => TOTP_DIGITS,
        'period'    => TOTP_PERIOD,
    ]);
    return "otpauth://totp/{$label}?{$query}";
}

function totp_code_at(string $secret, int $timestamp): string {
    $key = totp_base32_decode($secret);
    $counter = intdiv($timestamp, TOTP_PERIOD);
    $counterBin = pack('N*', 0, $counter); // 8-byte big-endian counter (high word always 0 until year ~2106)

    $hash = hash_hmac('sha1', $counterBin, $key, true);
    $offset = ord($hash[19]) & 0x0F;
    $truncated = ((ord($hash[$offset]) & 0x7F) << 24)
               | ((ord($hash[$offset + 1]) & 0xFF) << 16)
               | ((ord($hash[$offset + 2]) & 0xFF) << 8)
               | (ord($hash[$offset + 3]) & 0xFF);
    $code = $truncated % (10 ** TOTP_DIGITS);
    return str_pad((string)$code, TOTP_DIGITS, '0', STR_PAD_LEFT);
}

/** Verifies a 6-digit code allowing +/- $window steps of clock drift. */
function totp_verify(string $secret, string $code, int $window = 1, ?int $timestamp = null): bool {
    $code = trim($code);
    if (!preg_match('/^\d{' . TOTP_DIGITS . '}$/', $code)) {
        return false;
    }
    $timestamp = $timestamp ?? time();
    for ($i = -$window; $i <= $window; $i++) {
        $candidate = totp_code_at($secret, $timestamp + ($i * TOTP_PERIOD));
        if (hash_equals($candidate, $code)) {
            return true;
        }
    }
    return false;
}
