# PHP Drop-in Auth

Simple session-based authentication for small PHP utilities. Supports named users with bcrypt-hashed passwords, CSRF protection, an 8-hour sliding session, and optional multi-factor authentication (TOTP, backup codes, and ntfy push challenge/response).

## Files

| File | Purpose |
|---|---|
| `auth.php` | Auth guard — require this at the top of each utility |
| `auth_users.php.EXAMPLE` | Template for the legacy password-only users file |
| `auth_users.ini.EXAMPLE` | Template for the `.ini` users file (required for MFA) |
| `login.php` | Login form |
| `logout.php` | Destroys session and redirects to login |
| `manage_users.php` | CLI backend for user management (called by `authctl`) |
| `authctl` | Shell wrapper — the main tool for day-to-day user management |
| `mfa_config.php` | MFA constants — include-only, not a web endpoint |
| `mfa_store.php` | MFA data layer (ini parsing, merge, locked writes) — include-only |
| `mfa_totp.php` | RFC 6238 TOTP implementation — include-only |
| `mfa_ntfy.php` | ntfy.sh push challenge/response helper — include-only |
| `mfa_qr.php` | QR code rendering via the `qrencode` binary — include-only |
| `mfa_session.php` | Shared pending-MFA session helpers — include-only |
| `branding.php` | Shared UI branding loader — include-only, used by `login.php`, `mfa_verify.php`, and `mfa_enroll.php` |
| `mfa_verify.php` | Second-factor verification page, reached after password login |
| `mfa_check.php` | Background poll endpoint `mfa_verify.php` uses for ntfy replies |
| `mfa_enroll.php` | Self-service MFA enrollment page (opt-in, see below) |
| `mfa_enroll_check.php` | Background poll endpoint `mfa_enroll.php` uses for ntfy replies |
| `.htaccess` | Blocks web access to sensitive files (Apache) |
| `simplewebauth-nginx.conf` | Nginx snippet — equivalent protection for Nginx servers |
| `simplewebauth-config.php.EXAMPLE` | Template for docroot UI customization (copy to parent directory) |

## Setup

### 1. Deploy the simplewebauth directory

Copy this directory to your web root (or a subdirectory). A common layout:

```
/var/www/html/
├── simplewebauth/
│   ├── auth.php
│   ├── auth_users.php.EXAMPLE
│   ├── authctl
│   ├── login.php
│   ├── logout.php
│   ├── manage_users.php
│   └── .htaccess
├── tool1.php
├── tool2.php
└── tool3.php

/etc/simplewebauth/          ← created automatically by authctl
└── auth_users.php           ← live user database (owner: root:<webuser> 640)
```

### 2. Add users

Run from the server CLI (not via the browser). The first `add` creates `/etc/simplewebauth/` with correct ownership and permissions automatically — run with `sudo` so it can do that:

```bash
sudo ./simplewebauth/authctl add alice
# prompts for password
```

Subsequent `add`, `passwd`, and `remove` commands also work without `sudo` once the directory exists, but running with `sudo` ensures file permissions stay tight (`root:<webuser> 640`).

Passwords must be at least 8 characters. Hashes are written to `/etc/simplewebauth/auth_users.php`.

### 3. Protect each utility

Add one line at the very top of each PHP file you want to protect:

```php
<?php
require __DIR__ . '/simplewebauth/auth.php';

// ... rest of your script
```

Adjust the path if your utility lives in a subdirectory relative to `simplewebauth/`:

```php
require __DIR__ . '/../simplewebauth/auth.php';   // one level up
require '/var/www/html/simplewebauth/auth.php';   // absolute path always works
```

That's it. Unauthenticated requests are redirected to the login page and returned to the original URL after a successful login.

## Managing users

Use `authctl`, the shell wrapper around `manage_users.php`. It auto-detects its
own location so it works from any directory.

```bash
# Make it executable once after deployment
chmod +x simplewebauth/authctl

# Optionally symlink it onto your PATH for convenience
sudo ln -s /var/www/html/simplewebauth/authctl /usr/local/bin/authctl
```

### Commands

```bash
# List all users
authctl list

# Add a user (prompts for password)
authctl add <username>

# Change a user's password (prompts for new password)
authctl passwd <username>

# Remove a user (asks for confirmation before deleting)
authctl remove <username>

# Verify that php and manage_users.php are found and working
authctl check

# Convert the legacy auth_users.php to the .ini format (required for MFA)
authctl migrate

# MFA management — see "Multi-factor authentication" below
authctl mfa new <username>
authctl mfa pending
authctl mfa merge
authctl mfa disable <username>
```

### Help

```bash
authctl --help            # general help
authctl add --help        # help for a specific command
authctl remove --help
authctl passwd --help
```

### Aliases

`remove` also accepts `rm` and `del` as shorthand.

## Showing the logged-in user / logout link

`auth.php` exposes a helper function `auth_user()` that returns the current username. Use it anywhere after the require:

```php
<?php
require __DIR__ . '/simplewebauth/auth.php';
?>
<!DOCTYPE html>
<html>
<body>
  <p>Logged in as: <?= htmlspecialchars(auth_user()) ?></p>
  <a href="/simplewebauth/logout.php">Sign out</a>

  <!-- your utility content here -->
</body>
</html>
```

## Configuration

Settings are constants defined at the top of `auth.php`:

| Constant | Default | Description |
|---|---|---|
| `AUTH_SESSION_LIFETIME` | `28800` | Session timeout in seconds (default: 8 hours) |
| `AUTH_SESSION_NAME` | `phpauth` | Cookie name for the session |
| `AUTH_LOGIN_PAGE` | `simplewebauth/login.php` | Absolute filesystem path to the login page |

Edit `auth.php` directly to change these. MFA adds its own set of constants — see [Multi-factor authentication](#multi-factor-authentication) below.

## Security notes

- **`auth_users.php` lives at `/etc/simplewebauth/auth_users.php`**, outside the docroot entirely — it cannot be served by the web server regardless of any config. The `.htaccess` and nginx snippet no longer need to block it.
- **Never run `manage_users.php` via the browser** — the `.htaccess`/nginx snippet blocks it, but keep it off publicly accessible paths anyway.
- `authctl`, `README.md`, and `LICENSE` are blocked from web access by `.htaccess`.
- Verify Apache has `AllowOverride All` (or at minimum `AllowOverride AuthConfig Limit`) enabled for your directory, otherwise `.htaccess` rules are silently ignored.
- `/etc/simplewebauth/` is created with `root:<webuser> 750` and `auth_users.php` with `root:<webuser> 640` — the web server process can read but not write the file, and other system users cannot read it at all.
- Sessions use `HttpOnly`, `SameSite=Lax`, and `Strict` mode cookies. If your site runs over HTTPS, the `Secure` flag is added automatically.
- Login attempts are throttled with a 300ms delay on failure to slow brute force attacks. For internet-facing tools, consider adding fail2ban or rate limiting at the Apache/nginx level as well.
- The `redirect` parameter on the login page is validated to prevent open redirects — only same-host URLs are allowed.
- MFA-specific security notes (ntfy topic secrecy, backup-code guarantees, push-fatigue defense model) are covered in [Multi-factor authentication](#multi-factor-authentication).

## Login page customization

The login page can be branded without touching any file inside the `simplewebauth/` directory. Copy the example config to your docroot:

```bash
cp simplewebauth/simplewebauth-config.php.EXAMPLE simplewebauth-config.php
```

Then edit `simplewebauth-config.php` to taste:

```php
<?php
if (!defined('AUTH_DIR')) { http_response_code(403); exit; }

return [
    'app_name'    => 'My Tools',          // page <title> and card heading
    'logo_url'    => '/logo.png',         // logo above the heading (omit to hide)
    'logo_alt'    => 'My Tools',          // alt text for the logo
    'banner'      => 'Authorized users only.',  // subtitle beneath heading (HTML)
    'footer'      => '&copy; 2026 ACME Corp',  // below the card (HTML)
    'bg_image_url'=> '/bg.jpg',           // full-screen background image
    'bg_overlay'  => 'rgba(0,0,0,0.45)', // scrim over image (omit for default, '' to disable)
];
```

**Notes:**
- The file lives in the docroot (`../simplewebauth-config.php` relative to the `simplewebauth/` directory) — git pulls never touch it.
- `banner` and `footer` are rendered as raw HTML, so tags, entities, and links work.
- `app_name`, `logo_*`, `bg_image_url`, and `bg_overlay` are plain text/CSS values and are escaped before output.
- `bg_image_url` uses `background-size: cover` — the image fills the screen and maintains its aspect ratio, cropping whichever axis doesn't fit. This is the standard professional login background behavior.
- `bg_overlay` defaults to `rgba(0,0,0,0.45)` whenever a background image is set — a subtle dark scrim that ensures the white card is readable against any image. Set it to a brand color (`rgba(30,60,120,0.5)`) for a tinted look, or `''` to disable it entirely.
- The self-guard at the top (`if (!defined('AUTH_DIR'))`) blocks direct browser access to the file without needing extra web server rules.
- Omit any key to fall back to the default (no logo, no banner, no footer, no background image; heading reads "Sign in").

## Overriding the users file path

The default path `/etc/simplewebauth/auth_users.php` can be changed by defining `AUTH_USERS_FILE` before requiring `auth.php`:

```php
<?php
define('AUTH_USERS_FILE', '/srv/myapp/users.php');
require __DIR__ . '/simplewebauth/auth.php';
```

Update `authctl`'s `USERS_DIR` and `USERS_FILE` variables at the top of the script to match.

## Multi-factor authentication

MFA is fully backward compatible: an existing install using the legacy `auth_users.php` format keeps working, password-only, with zero changes. MFA becomes available the moment an install migrates to the `.ini` format — the legacy scalar format simply can't carry the extra fields.

Three methods are supported per user, in any combination:

- **TOTP** — any standard authenticator app (Google Authenticator, Authy, FreeOTP, etc.)
- **Backup codes** — one-time-use recovery codes, generated alongside the first method enrolled
- **ntfy push challenge** — a push notification via [ntfy](https://ntfy.sh) (or a self-hosted instance) showing a short code; replying with that code approves the sign-in. Fires immediately on password success, in parallel with the code-entry field — not something the user has to request. An unsolicited push is itself a signal the password may be compromised.

At login, if a user has MFA enabled, any enrolled method can complete it — a single field accepts either a TOTP code (6 digits) or a backup code (10 characters), dispatched automatically by length. Wrong attempts, a wrong ntfy reply, and an ntfy challenge timing out all count against one shared limit (3 by default) — hitting it resets all the way back to the password prompt.

### Requirements

- The users file must be `.ini` format (`authctl migrate` converts an existing legacy install in place, non-destructively — the original `.php` file is left untouched).
- The `qrencode` binary must be installed on the server for QR codes to render (`apt install qrencode` / `dnf install qrencode`). Without it, enrollment still works — it falls back to showing the raw secret/URL as text to enter manually.
- ntfy push requires outbound HTTPS access from the server to whichever ntfy server is configured (`https://ntfy.sh` by default, or your own self-hosted instance).

### Two ways to enroll a user

**Vault/Ansible-driven (offline, no server write):**

```bash
authctl mfa new alice
```

Prints a TOTP secret + QR, an ntfy topic URL + QR, and a set of backup codes — plus a ready-to-paste `.ini` stanza combining all of it. Nothing is written to any file; this is meant to be pasted into a vault-encrypted source and pushed out by your existing Ansible flow. Requires the user to already exist (`authctl add`).

**Self-service (a user enrolls their own second factor):**

Off by default. Enable by defining, before `auth.php` is required (e.g. alongside other `AUTH_*` constants):

```php
define('AUTH_ALLOW_SELF_MFA', true);
```

Then link an already-authenticated user to `mfa_enroll.php` (e.g. from wherever you show the logout link). It walks through TOTP and/or ntfy enrollment, requiring proof of possession — a correct current code, or a confirmed ntfy reply — before anything is saved, so a mis-scanned QR or unreachable ntfy topic can never silently lock in a broken second factor. Backup codes are generated and shown exactly once, the first time either method is confirmed.

Self-enrolled data is written to a **separate overlay file**, never the vault-managed main file, and can never contain a password — a section only exists there for a user who already authenticated with a real password against the main file, so a compromise of the overlay alone can't create or impersonate an account. If a fleet is also vault-managed, the main file always wins field-by-field over the overlay, so a central push (including an explicit `mfa_enabled = false` kill switch) always supersedes anything a user self-enrolled.

To fold self-enrolled data into your vault source: `authctl mfa pending` lists it and prints a fully-assembled stanza (real password hash + the new MFA fields) ready to paste. Once captured and pushed back down, `authctl mfa merge` prunes the now-redundant overlay entries — safe to run anytime, including on a schedule.

### File locations

| File | Path | Written by |
|---|---|---|
| Main users file | wherever `AUTH_USERS_FILE` points, `.ini` format | sysadmin / Ansible only |
| Self-enrollment overlay | `AUTH_USERS_LOCAL_FILE` (default `/var/local/simplewebauth/auth_users_local.ini`) | the web server process |
| Burned backup-code ledger | `AUTH_BURNED_CODES_FILE` (default `/var/local/simplewebauth/burned_codes_local.ini`) | the web server process |

The main file stays exactly where host configuration belongs (`/etc/simplewebauth/`), read-only to the web server, unchanged from today. The two overlay files live under `/var/local/simplewebauth/` instead — the FHS convention for a locally-installed, unpackaged service's own runtime state — and are created automatically (`0700`, owned by the web user) the first time anything is written to them. Both directories/files need `authctl`'s permission-fixing step re-run if a root-run command (`authctl mfa merge`/`mfa disable`) touches the overlay file; `authctl` does this for you automatically.

Backup-code one-time-use is a **per-host guarantee**, not a fleet-wide one — a code burned on one server isn't known to another. Deliberate trade-off for a small, flat-file, no-database tool; fine for a small user base, worth knowing if you run several load-balanced instances behind one login domain.

### Configuration constants

| Constant | Default | Description |
|---|---|---|
| `AUTH_USERS_LOCAL_FILE` | `/var/local/simplewebauth/auth_users_local.ini` | Self-enrollment overlay path |
| `AUTH_BURNED_CODES_FILE` | `/var/local/simplewebauth/burned_codes_local.ini` | Backup-code ledger path |
| `AUTH_ALLOW_SELF_MFA` | `false` | Enables `mfa_enroll.php` / `mfa_enroll_check.php` |
| `AUTH_NTFY_SERVER` | `https://ntfy.sh` | Default server for minting new topics during self-enrollment only — the stored `ntfy_url` is a full self-contained URL, never reconstructed from this constant afterward |
| `AUTH_MFA_PENDING_LIFETIME` | `300` (5 min) | How long a password-verified, second-factor-pending session stays valid |
| `AUTH_MFA_MAX_ATTEMPTS` | `3` | Shared strike limit across all methods before resetting to password login |
| `AUTH_MFA_NTFY_CHALLENGE_TTL` | `90` (seconds) | ntfy challenge expiry; a timeout counts as one strike |
| `AUTH_MFA_BACKUP_CODE_COUNT` | `10` | Backup codes generated per enrollment |
| `AUTH_MFA_BACKUP_CODE_LENGTH` | `10` | Characters per backup code |

Define any of these before requiring `mfa_store.php` (transitively, before `auth.php`/`login.php` run) to override.

### MFA security notes

- The ntfy topic URL is a **bearer secret** on the public server — anyone who knows it can publish/subscribe. It's generated with a CSPRNG, never logged, and handled with the same care as the TOTP secret.
- The ntfy challenge is deliberately low-entropy (2 characters) — the same technique as Microsoft Authenticator's "number matching." Its job is defeating blind push-fatigue spam-approval attacks, not brute-force resistance, and it does **not** defend against a real-time adversary-in-the-middle relaying a live phishing session.
- **The code is shown only on the browser doing the sign-in, never in the push notification itself.** The push is a content-free "someone's signing in, check your screen" notice. This is what makes number-matching actually work: mere read access to the ntfy topic tells an attacker nothing, since they'd also need eyes on the live login screen to know what to reply with. Embedding the code in the push instead — so the phone just echoes back what it was told — would collapse the whole mechanism to "anyone who can read this topic can approve," which defeats the point of a second factor entirely.
- `qrencode` is invoked with the data piped through **stdin**, never as a command-line argument — an argv value briefly appears in the process table, readable by any other local user running `ps aux` at the wrong moment.
- All writes to the overlay/ledger files share one locking helper (`flock`-guarded read-modify-write + atomic rename), used identically by the web runtime and `authctl` — there's no second, independently-written implementation to drift out of sync.
- Backup codes are bcrypt-hashed at rest everywhere, exactly like passwords.

## Web server configuration

### Apache

`.htaccess` rules require `AllowOverride` to be enabled. In your Apache config or `/etc/apache2/sites-available/yoursite.conf`:

```apache
<Directory /var/www/html>
    AllowOverride All
</Directory>
```

Then reload Apache:

```bash
sudo systemctl reload apache2
```

### Nginx

Nginx does not read `.htaccess` files — the snippet `simplewebauth-nginx.conf` provides the equivalent protection.

**Why not `conf.d/`?** Files in `conf.d/` load at the `http {}` level where `location` blocks are not valid. The correct Nginx pattern is a snippet file included inside each `server {}` block — the rule lives in one place, you just reference it everywhere it's needed.

**Install the snippet:**

```bash
sudo cp simplewebauth-nginx.conf /etc/nginx/snippets/simplewebauth.conf
```

**Add one line to each `server {}` block** in your site config (e.g. `/etc/nginx/sites-available/yoursite.conf`):

```nginx
server {
    listen 80;
    server_name example.com;
    root /var/www/html;

    include snippets/simplewebauth.conf;   # ← add this

    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php-fpm.sock;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }
}
```

The pattern matches `manage_users.php` inside any folder named `simplewebauth`, at any depth under the docroot. `auth_users.php` no longer needs to be blocked — it lives outside the docroot entirely.

Then reload Nginx:

```bash
sudo nginx -t && sudo systemctl reload nginx
```
