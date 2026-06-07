<?php
/**
 * CLI user manager for auth_users.php
 *
 * Usage:
 *   php manage_users.php list
 *   php manage_users.php add <username> <password>
 *   php manage_users.php remove <username>
 *   php manage_users.php passwd <username> <newpassword>
 */

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    exit('CLI only.');
}

$usersFile = __DIR__ . '/auth_users.php';

function load_users(string $file): array {
    if (!file_exists($file)) return [];
    $data = require $file;
    return is_array($data) ? $data : [];
}

function save_users(string $file, array $users): void {
    $lines = ["<?php\n// User database — managed by manage_users.php\n\nreturn [\n"];
    foreach ($users as $u => $h) {
        $eu = addslashes($u);
        $eh = addslashes($h);
        $lines[] = "    '$eu' => '$eh',\n";
    }
    $lines[] = "];\n";
    file_put_contents($file, implode('', $lines));
}

function hash_password(string $password): string {
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

function prompt_password(string $prompt): string {
    echo $prompt;
    system('stty -echo');
    $pass = trim(fgets(STDIN));
    system('stty echo');
    echo "\n";
    return $pass;
}

$cmd = $argv[1] ?? 'help';

switch ($cmd) {
    case 'list':
        $users = load_users($usersFile);
        if (empty($users)) {
            echo "No users configured.\n";
        } else {
            echo "Users:\n";
            foreach (array_keys($users) as $u) {
                echo "  - $u\n";
            }
        }
        break;

    case 'add':
        $username = $argv[2] ?? '';
        if ($username === '') { echo "Usage: php manage_users.php add <username> [password]\n"; exit(1); }
        $users = load_users($usersFile);
        if (isset($users[$username])) { echo "User '$username' already exists. Use 'passwd' to change password.\n"; exit(1); }
        $password = $argv[3] ?? prompt_password("Password for $username: ");
        if (strlen($password) < 8) { echo "Password must be at least 8 characters.\n"; exit(1); }
        $users[$username] = hash_password($password);
        save_users($usersFile, $users);
        echo "Added user '$username'.\n";
        break;

    case 'remove':
        $username = $argv[2] ?? '';
        if ($username === '') { echo "Usage: php manage_users.php remove <username>\n"; exit(1); }
        $users = load_users($usersFile);
        if (!isset($users[$username])) { echo "User '$username' not found.\n"; exit(1); }
        unset($users[$username]);
        save_users($usersFile, $users);
        echo "Removed user '$username'.\n";
        break;

    case 'passwd':
        $username = $argv[2] ?? '';
        if ($username === '') { echo "Usage: php manage_users.php passwd <username> [newpassword]\n"; exit(1); }
        $users = load_users($usersFile);
        if (!isset($users[$username])) { echo "User '$username' not found. Use 'add' to create.\n"; exit(1); }
        $password = $argv[3] ?? prompt_password("New password for $username: ");
        if (strlen($password) < 8) { echo "Password must be at least 8 characters.\n"; exit(1); }
        $users[$username] = hash_password($password);
        save_users($usersFile, $users);
        echo "Password updated for '$username'.\n";
        break;

    default:
        echo <<<HELP
manage_users.php — auth_users.php manager

Commands:
  list                          List all users
  add <username> [password]     Add a new user
  remove <username>             Remove a user
  passwd <username> [password]  Change a user's password

HELP;
}
