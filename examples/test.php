<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Session Timeout Test</title>
    <style>
        body { font-family: monospace; padding: 20px; }
        .info { background: #e3f2fd; padding: 10px; margin: 10px 0; }
        .warning { background: #fff3cd; padding: 10px; margin: 10px 0; }
        .error { background: #f8d7da; padding: 10px; margin: 10px 0; }
        .success { background: #d4edda; padding: 10px; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>Session Timeout Debug Page</h1>

<?php
require __DIR__ . '/../vendor/autoload.php';

use SecureSession\SecurityConfig;
use SecureSession\Logger;
use SecureSession\SessionManager;
use SecureSession\AnomalyDetector;
use SecureSession\Storage\SqliteStorage;

$config = new SecurityConfig();
// Set a SHORT timeout for testing
$config->idleTimeout = 30; // 30 seconds

$storage = new SqliteStorage(__DIR__ . '/../data/session_logs.sqlite');
$secret = getenv('SESSION_LOG_HMAC') ?: 'change_me_in_env';
$logger = new Logger($storage, $secret);
$anomaly = new AnomalyDetector();

$sm = new SessionManager($config, $logger, $anomaly);

echo "<div class='info'><strong>BEFORE start():</strong><br>";
echo "Session Status: " . session_status() . "<br>";
echo "Session Cookie Exists: " . (isset($_COOKIE[session_name()]) ? 'YES' : 'NO') . "<br>";
echo "</div>";

$sm->start();

echo "<div class='info'><strong>AFTER start():</strong><br>";
echo "Session ID: " . session_id() . "<br>";
echo "Session Status: " . session_status() . "<br>";
echo "</div>";

// Handle login
if (isset($_POST['login'])) {
    $sm->set('user_id', 'testuser');
    $sm->set('login_time', time());
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Handle logout
if (isset($_GET['logout'])) {
    $sm->destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Display session info
if ($sm->get('user_id')) {
    echo "<div class='success'>";
    echo "<h2>✅ LOGGED IN</h2>";
    echo "<strong>User ID:</strong> " . htmlspecialchars($sm->get('user_id')) . "<br>";
    echo "<strong>Login Time:</strong> " . date('Y-m-d H:i:s', $sm->get('login_time')) . "<br>";
    
    if (isset($_SESSION['meta'])) {
        echo "<br><strong>Session Meta:</strong><br>";
        echo "Created: " . $_SESSION['meta']['created_at'] . "<br>";
        echo "Last Activity: " . date('Y-m-d H:i:s', $_SESSION['meta']['last_activity']) . "<br>";
        
        $idleTime = time() - $_SESSION['meta']['last_activity'];
        $remaining = $config->idleTimeout - $idleTime;
        
        echo "<br><strong>Timeout Info:</strong><br>";
        echo "Idle Time: {$idleTime} seconds<br>";
        echo "Timeout Limit: {$config->idleTimeout} seconds<br>";
        echo "Time Remaining: {$remaining} seconds<br>";
        
        if ($remaining < 0) {
            echo "<div class='error'>⚠️ Session SHOULD be expired!</div>";
        } elseif ($remaining < 10) {
            echo "<div class='warning'>⚠️ Session expiring soon!</div>";
        }
    }
    
    echo "<br><a href='?logout=1' style='padding: 10px; background: #dc3545; color: white; text-decoration: none;'>Logout</a>";
    echo "<br><br><small>Refresh this page to update. Leave idle for {$config->idleTimeout} seconds to test auto-logout.</small>";
    echo "</div>";
} else {
    echo "<div class='warning'>";
    echo "<h2>🔓 NOT LOGGED IN</h2>";
    
    // Check if session was destroyed due to timeout
    if (isset($_SESSION) && empty($_SESSION) && isset($_COOKIE[session_name()])) {
        echo "<div class='error'><strong>⚠️ Your session may have expired due to inactivity.</strong></div>";
    }
    
    echo "<form method='POST'>";
    echo "<button type='submit' name='login' style='padding: 10px; background: #007bff; color: white; border: none; cursor: pointer;'>Login as testuser</button>";
    echo "</form>";
    echo "<br><small>After login, leave this page idle for {$config->idleTimeout} seconds and refresh.</small>";
    echo "</div>";
}

echo "<div class='info'>";
echo "<strong>Full \$_SESSION dump:</strong><br>";
echo "<pre>" . print_r($_SESSION, true) . "</pre>";
echo "</div>";
?>

<div class='info'>
    <strong>Current Time:</strong> <?= date('Y-m-d H:i:s') ?><br>
    <strong>Page loaded at:</strong> <?= date('Y-m-d H:i:s') ?>
</div>

</body>
</html>