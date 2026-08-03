<?php
/**
 * Shared login-flow UI branding — loaded from an optional
 * simplewebauth-config.php in the docroot (one level up, outside the code
 * tree). Used by login.php, mfa_verify.php, and mfa_enroll.php so the whole
 * authentication flow shares one visual identity, not just the first screen.
 */

function auth_branding(): array {
    $ui = [];
    $uiConfigFile = dirname(__DIR__) . '/simplewebauth-config.php';
    if (is_file($uiConfigFile)) {
        $ui = (array)(require $uiConfigFile);
    }
    return [
        'app_name'     => htmlspecialchars($ui['app_name'] ?? 'Sign in', ENT_QUOTES),
        'logo_url'     => htmlspecialchars($ui['logo_url'] ?? '', ENT_QUOTES),
        'logo_alt'     => htmlspecialchars($ui['logo_alt'] ?? '', ENT_QUOTES),
        'banner'       => $ui['banner'] ?? '', // rendered as HTML — admin-controlled
        'footer'       => $ui['footer'] ?? '', // rendered as HTML — admin-controlled
        'bg_image_url' => htmlspecialchars($ui['bg_image_url'] ?? '', ENT_QUOTES),
        'bg_overlay'   => htmlspecialchars(
            array_key_exists('bg_overlay', $ui) ? (string)$ui['bg_overlay'] : 'rgba(0,0,0,0.45)',
            ENT_QUOTES
        ),
    ];
}
