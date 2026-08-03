<?php
/**
 * ntfy.sh (or self-hosted equivalent) push challenge/response.
 *
 * The stored value is always the FULL topic URL (server + topic) — one
 * opaque string does both jobs: POST to it to publish, GET its /json
 * endpoint to read replies. Never reconstructed from separate parts.
 */

/** ntfy topic names only permit [A-Za-z0-9_-] — encode, don't pass raw bytes. */
function ntfy_generate_topic_url(string $server): string {
    $token = rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '=');
    $token = preg_replace('/[^A-Za-z0-9_-]/', '', $token);
    return rtrim($server, '/') . '/swauth-' . $token;
}

/** 2-char challenge, alphanumeric, excluding ambiguous glyphs (0/O, 1/I/L). */
function ntfy_generate_challenge(): string {
    $alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
    $out = '';
    for ($i = 0; $i < 2; $i++) {
        $out .= $alphabet[random_int(0, strlen($alphabet) - 1)];
    }
    return $out;
}

function ntfy_http_request(string $url, string $method, ?string $body = null, array $headers = [], int $timeoutSeconds = 8) {
    $headerLines = $headers;
    $options = [
        'http' => [
            'method'        => $method,
            'header'        => implode("\r\n", $headerLines),
            'content'       => $body,
            'timeout'       => $timeoutSeconds,
            'ignore_errors' => true,
        ],
    ];
    $context = stream_context_create($options);
    $result = @file_get_contents($url, false, $context);
    if ($result === false) {
        return false;
    }
    $status = 0;
    if (isset($http_response_header[0]) && preg_match('/\s(\d{3})\s/', $http_response_header[0], $m)) {
        $status = (int)$m[1];
    }
    return ['status' => $status, 'body' => $result];
}

/** Publishes a challenge/notice to the given topic URL. Never throws — returns bool. */
function ntfy_publish(string $topicUrl, string $title, string $message): bool {
    $response = ntfy_http_request($topicUrl, 'POST', $message, [
        'Content-Type: text/plain; charset=utf-8',
        'Title: ' . $title,
    ]);
    return $response !== false && $response['status'] >= 200 && $response['status'] < 300;
}

/**
 * Returns the trimmed, uppercased bodies of messages received on the topic
 * since $sinceTimestamp (unix epoch seconds). Never throws — empty array on
 * any transport failure, so a flaky network just means "no reply yet".
 */
function ntfy_poll_since(string $topicUrl, int $sinceTimestamp): array {
    $url = rtrim($topicUrl, '/') . '/json?poll=1&since=' . $sinceTimestamp;
    $response = ntfy_http_request($url, 'GET');
    if ($response === false || $response['status'] !== 200) {
        return [];
    }
    $messages = [];
    foreach (preg_split('/\r?\n/', trim($response['body'])) as $line) {
        if ($line === '') {
            continue;
        }
        $decoded = json_decode($line, true);
        if (is_array($decoded) && ($decoded['event'] ?? '') === 'message' && isset($decoded['message'])) {
            $messages[] = strtoupper(trim((string)$decoded['message']));
        }
    }
    return $messages;
}

/** True if a reply matching $expectedChallenge has arrived since $sinceTimestamp. */
function ntfy_check_challenge(string $topicUrl, string $expectedChallenge, int $sinceTimestamp): bool {
    $expected = strtoupper(trim($expectedChallenge));
    foreach (ntfy_poll_since($topicUrl, $sinceTimestamp) as $reply) {
        if (hash_equals($expected, $reply)) {
            return true;
        }
    }
    return false;
}
