<?php
require __DIR__ . '/../vendor/autoload.php';

use SecureSession\SecurityConfig;
use SecureSession\Logger;
use SecureSession\SessionManager;
use SecureSession\AnomalyDetector;
use SecureSession\Storage\SqliteStorage;

$config = new SecurityConfig();
$storage = new SqliteStorage(__DIR__ . '/../data/session_logs.sqlite');
// secret key from env (do not commit)
$secret = getenv('SESSION_LOG_HMAC') ?: 'change_me_in_env';
$logger = new Logger($storage, $secret);
$anomaly = new AnomalyDetector();

$sm = new SessionManager($config, $logger, $anomaly);
$sm->start(); // starts secure session

// simple auth demo

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['username'] === 'test' && $_POST['password'] === 'pass') {
    $sm->set('user_id', 'test');
    $sm->regenerate();
    
    echo "Logged in and session regenerated.";
    echo "<p>Session regenerated.</p>";
    
echo "<pre>Old session id: " . htmlspecialchars($result['old']) . "\n";
echo "New session id: " . htmlspecialchars($result['new']) . "</pre>";

    echo "";
} else {
    echo "<form method='POST'><input name='username'><input name='password'><button>Login</button></form>";
}


