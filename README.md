# PHP Drop-in Auth

Simple session-based authentication for small PHP utilities. Supports named users with bcrypt-hashed passwords, CSRF protection, and an 8-hour sliding session.

## Files

| File | Purpose |
|---|---|
| `auth.php` | Auth guard — require this at the top of each utility |
| `auth_users.php.EXAMPLE` | Template for the users file — the live file lives outside the docroot |
| `login.php` | Login form |
| `logout.php` | Destroys session and redirects to login |
| `manage_users.php` | CLI backend for user management (called by `authctl`) |
| `authctl` | Shell wrapper — the main tool for day-to-day user management |
| `.htaccess` | Blocks web access to sensitive files (Apache) |
| `simplewebauth-nginx.conf` | Nginx snippet — equivalent protection for Nginx servers |

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

Edit `auth.php` directly to change these.

## Security notes

- **`auth_users.php` lives at `/etc/simplewebauth/auth_users.php`**, outside the docroot entirely — it cannot be served by the web server regardless of any config. The `.htaccess` and nginx snippet no longer need to block it.
- **Never run `manage_users.php` via the browser** — the `.htaccess`/nginx snippet blocks it, but keep it off publicly accessible paths anyway.
- `authctl`, `README.md`, and `LICENSE` are blocked from web access by `.htaccess`.
- Verify Apache has `AllowOverride All` (or at minimum `AllowOverride AuthConfig Limit`) enabled for your directory, otherwise `.htaccess` rules are silently ignored.
- `/etc/simplewebauth/` is created with `root:<webuser> 750` and `auth_users.php` with `root:<webuser> 640` — the web server process can read but not write the file, and other system users cannot read it at all.
- Sessions use `HttpOnly`, `SameSite=Lax`, and `Strict` mode cookies. If your site runs over HTTPS, the `Secure` flag is added automatically.
- Login attempts are throttled with a 300ms delay on failure to slow brute force attacks. For internet-facing tools, consider adding fail2ban or rate limiting at the Apache/nginx level as well.
- The `redirect` parameter on the login page is validated to prevent open redirects — only same-host URLs are allowed.

## Overriding the users file path

The default path `/etc/simplewebauth/auth_users.php` can be changed by defining `AUTH_USERS_FILE` before requiring `auth.php`:

```php
<?php
define('AUTH_USERS_FILE', '/srv/myapp/users.php');
require __DIR__ . '/simplewebauth/auth.php';
```

Update `authctl`'s `USERS_DIR` and `USERS_FILE` variables at the top of the script to match.

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
