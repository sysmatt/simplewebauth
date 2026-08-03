<?php
/**
 * QR code rendering via the `qrencode` CLI binary — avoids hand-rolled
 * Reed-Solomon encoding, and avoids leaking secrets to a third-party QR
 * image API. Install with: apt install qrencode / dnf install qrencode
 */

function qr_available(): bool {
    static $available = null;
    if ($available !== null) {
        return $available;
    }
    $proc = @proc_open(['qrencode', '--version'], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($proc)) {
        return $available = false;
    }
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exitCode = proc_close($proc);
    return $available = ($exitCode === 0);
}

/**
 * Renders $data as a QR code in the given qrencode output type (SVG for web
 * pages, ANSIUTF8 for terminal display).
 *
 * Data is piped via stdin, never passed as a command-line argument — an
 * argv value briefly appears in the process table, readable by any other
 * local user running `ps aux` at the wrong moment.
 *
 * Returns null (never throws) if qrencode is missing or fails, so callers
 * can show a clear setup error instead of a fatal.
 */
function qr_render(string $data, string $type = 'SVG'): ?string {
    if (!qr_available()) {
        return null;
    }
    $proc = @proc_open(
        ['qrencode', '-t', $type, '-r', '/dev/stdin', '-o', '-'],
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes
    );
    if (!is_resource($proc)) {
        return null;
    }
    fwrite($pipes[0], $data);
    fclose($pipes[0]);
    $output = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exitCode = proc_close($proc);
    if ($exitCode !== 0 || $output === false || $output === '') {
        return null;
    }
    return $output;
}

function qr_svg(string $data): ?string {
    return qr_render($data, 'SVG');
}
